package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/entra-forward-auth/internal/basicauth"
	"github.com/KazuhaHub/entra-forward-auth/internal/config"
)

func noEnv(string) (string, bool) { return "", false }

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"version"}, &out, io.Discard, noEnv); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "entra-forward-auth dev (unknown) go") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"healthy", []string{"-url", ok.URL + "/healthz"}, 0},
		{"unhealthy", []string{"-url", bad.URL + "/healthz"}, 1},
		{"unreachable", []string{"-url", "http://127.0.0.1:1/healthz", "-timeout", "1s"}, 1},
		{"bad url", []string{"-url", "://nope"}, 1},
		{"bad flag", []string{"-wat"}, 2},
		{"help", []string{"-h"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(append([]string{"healthcheck"}, tc.args...), io.Discard, io.Discard, noEnv); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHealthURL(t *testing.T) {
	tests := map[string]string{
		"":                 "http://127.0.0.1:5002/healthz",
		"127.0.0.1:5002":   "http://127.0.0.1:5002/healthz",
		"0.0.0.0:8080":     "http://127.0.0.1:8080/healthz",
		":9000":            "http://127.0.0.1:9000/healthz",
		"[::]:9001":        "http://[::1]:9001/healthz",
		"[::1]:9002":       "http://[::1]:9002/healthz",
		"10.1.2.3:7000":    "http://10.1.2.3:7000/healthz",
		"localhost:7001":   "http://localhost:7001/healthz",
		"garbage":          "http://127.0.0.1:5002/healthz",
		"127.0.0.1:":       "http://127.0.0.1:5002/healthz",
		"  0.0.0.0:6000  ": "http://127.0.0.1:6000/healthz",
	}
	for in, want := range tests {
		if got := healthURL(in); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHealthcheckDerivesURLFromListen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")
	env := func(k string) (string, bool) {
		if k == "LISTEN" {
			return addr, true
		}
		return "", false
	}
	if got := run([]string{"healthcheck"}, io.Discard, io.Discard, env); got != 0 {
		t.Fatalf("from LISTEN: exit %d", got)
	}
	if got := run([]string{"healthcheck", "-listen", addr}, io.Discard, io.Discard, noEnv); got != 0 {
		t.Fatalf("from -listen: exit %d", got)
	}
	if got := run([]string{"healthcheck", "-listen", "127.0.0.1:1", "-timeout", "1s"}, io.Discard, io.Discard, env); got != 1 {
		t.Fatalf("-listen must win over LISTEN: exit %d", got)
	}
}

func TestConfigErrorExitCode(t *testing.T) {
	var errOut bytes.Buffer
	if code := run(nil, io.Discard, &errOut, noEnv); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "ENTRA_TENANT_ID is required") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if code := run([]string{"-h"}, io.Discard, io.Discard, noEnv); code != 0 {
		t.Fatalf("-h exit %d", code)
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf, &config.Config{LogFormat: "json", LogLevel: slog.LevelInfo}).Info("x")
	if !strings.HasPrefix(buf.String(), "{") {
		t.Fatalf("not JSON: %q", buf.String())
	}
	buf.Reset()
	newLogger(&buf, &config.Config{LogFormat: "text", LogLevel: slog.LevelInfo}).Info("x")
	if !strings.Contains(buf.String(), "level=INFO") {
		t.Fatalf("not text: %q", buf.String())
	}
}

// fakeAuthority is a token endpoint accepting password "good".
func fakeAuthority(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("password") == "good" && (r.PostForm.Get("client_assertion") != "" || r.PostForm.Get("client_secret") == "topsecret") {
			_, _ = w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_codes":[50126]}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

type runningService struct {
	addrs  map[string]string
	cancel context.CancelFunc
	done   chan error
	reload chan os.Signal
	logs   *syncBuffer
}

func startService(t *testing.T, args []string, env map[string]string) *runningService {
	t.Helper()
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	cfg, err := config.Load(args, lookup, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	rs := &runningService{addrs: map[string]string{}, done: make(chan error, 1), reload: make(chan os.Signal, 1), logs: &syncBuffer{}}
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	rs.cancel = cancel
	logger := slog.New(slog.NewTextHandler(rs.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ready := make(chan struct{})
	var once sync.Once
	go func() {
		rs.done <- serve(ctx, cfg, logger, rs.reload, func(name string, a net.Addr) {
			mu.Lock()
			rs.addrs[name] = a.String()
			mu.Unlock()
			if len(rs.addrs) == 1 && cfg.MetricsListen == "" || len(rs.addrs) == 2 {
				once.Do(func() { close(ready) })
			}
		})
	}()
	select {
	case <-ready:
	case err := <-rs.done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("service did not start")
	}
	t.Cleanup(func() { cancel() })
	return rs
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (rs *runningService) stop(t *testing.T) {
	t.Helper()
	rs.cancel()
	select {
	case err := <-rs.done:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

// testClient never keeps connections open, so a graceful shutdown is not held
// up by idle (or speculatively dialled) client connections.
var testClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

func get(t *testing.T, url string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestServeSecretModeEndToEnd(t *testing.T) {
	authority := fakeAuthority(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("topsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs := startService(t, nil, map[string]string{
		"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c", "ENTRA_SCOPE": "s",
		"ENTRA_CLIENT_SECRET_FILE": secret, "ENTRA_AUTHORITY": authority.URL,
		"LISTEN": "127.0.0.1:0", "METRICS_LISTEN": "127.0.0.1:0",
	})
	base := "http://" + rs.addrs["main"]
	metricsBase := "http://" + rs.addrs["metrics"]

	if got := get(t, base+"/auth", map[string]string{"Authorization": basicauth.Encode("u@example.com", "good")}); got != 204 {
		t.Fatalf("auth good = %d", got)
	}
	if got := get(t, base+"/auth", map[string]string{"Authorization": basicauth.Encode("u@example.com", "bad")}); got != 401 {
		t.Fatalf("auth bad = %d", got)
	}
	if got := get(t, base+"/healthz", nil); got != 200 {
		t.Fatalf("healthz = %d", got)
	}
	if got := get(t, base+"/metrics", nil); got != 404 {
		t.Fatalf("main /metrics = %d, want 404 with a separate listener", got)
	}
	if got := get(t, metricsBase+"/metrics", nil); got != 200 {
		t.Fatalf("metrics = %d", got)
	}
	rs.reload <- syscall.SIGHUP // nothing to reload in secret mode; must not crash
	time.Sleep(50 * time.Millisecond)
	rs.stop(t)
	if strings.Contains(rs.logs.String(), "topsecret") {
		t.Fatal("secret leaked into logs")
	}
}

func writeCert(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestServeCertModeAndReload(t *testing.T) {
	authority := fakeAuthority(t)
	dir := t.TempDir()
	certPath, keyPath := writeCert(t, dir, time.Now().Add(10*24*time.Hour)) // soon-to-expire: warns
	rs := startService(t, []string{"-listen", "127.0.0.1:0"}, map[string]string{
		"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c", "ENTRA_SCOPE": "s",
		"ENTRA_CLIENT_CERT": certPath, "ENTRA_CLIENT_KEY": keyPath, "ENTRA_AUTHORITY": authority.URL,
	})
	base := "http://" + rs.addrs["main"]
	if got := get(t, base+"/readyz", nil); got != 200 {
		t.Fatalf("readyz = %d", got)
	}
	if got := get(t, base+"/auth", map[string]string{"Authorization": basicauth.Encode("u@example.com", "good")}); got != 204 {
		t.Fatalf("auth = %d", got)
	}
	if got := get(t, base+"/metrics", nil); got != 200 {
		t.Fatalf("metrics on main = %d", got)
	}

	// Successful reload.
	writeCert(t, dir, time.Now().Add(365*24*time.Hour))
	rs.reload <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Contains(rs.logs.String(), "credential reloaded") })

	// Failed reload keeps serving.
	if err := os.WriteFile(keyPath, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs.reload <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Contains(rs.logs.String(), "credential reload failed") })
	if got := get(t, base+"/auth", map[string]string{"Authorization": basicauth.Encode("v@example.com", "good")}); got != 204 {
		t.Fatalf("auth after failed reload = %d", got)
	}
	if !strings.Contains(rs.logs.String(), "client certificate expires soon") {
		t.Fatal("expected expiry warning")
	}
	rs.stop(t)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeStartupErrors(t *testing.T) {
	dir := t.TempDir()
	mk := func(env map[string]string) *config.Config {
		t.Helper()
		base := map[string]string{"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c", "ENTRA_SCOPE": "s", "LISTEN": "127.0.0.1:0"}
		for k, v := range env {
			base[k] = v
		}
		cfg, err := config.Load(nil, func(k string) (string, bool) { v, ok := base[k]; return v, ok }, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte(" \n"), 0o600)

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing secret file", map[string]string{"ENTRA_CLIENT_SECRET_FILE": filepath.Join(dir, "nope")}, "read client secret file"},
		{"empty secret file", map[string]string{"ENTRA_CLIENT_SECRET_FILE": empty}, "empty"},
		{"missing cert", map[string]string{"ENTRA_CLIENT_CERT": filepath.Join(dir, "nope"), "ENTRA_CLIENT_KEY": filepath.Join(dir, "nope")}, "read certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := serve(context.Background(), mk(tc.env), slog.New(slog.DiscardHandler), nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}

	// Listen address already taken.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	secret := filepath.Join(dir, "secret")
	_ = os.WriteFile(secret, []byte("x"), 0o600)
	cfg := mk(map[string]string{"ENTRA_CLIENT_SECRET_FILE": secret, "LISTEN": l.Addr().String()})
	if err := serve(context.Background(), cfg, slog.New(slog.DiscardHandler), nil, nil); err == nil || !strings.Contains(err.Error(), "listen main") {
		t.Fatalf("err = %v", err)
	}
	cfg = mk(map[string]string{"ENTRA_CLIENT_SECRET_FILE": secret, "METRICS_LISTEN": l.Addr().String()})
	if err := serve(context.Background(), cfg, slog.New(slog.DiscardHandler), nil, nil); err == nil || !strings.Contains(err.Error(), "listen metrics") {
		t.Fatalf("err = %v", err)
	}
}

func TestShutdownDrainKeepsServingWithReadyzFailing(t *testing.T) {
	authority := fakeAuthority(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("topsecret"), 0o600); err != nil {
		t.Fatal(err)
	}
	const drain = 400 * time.Millisecond
	rs := startService(t, nil, map[string]string{
		"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c", "ENTRA_SCOPE": "s",
		"ENTRA_CLIENT_SECRET_FILE": secret, "ENTRA_AUTHORITY": authority.URL,
		"LISTEN": "127.0.0.1:0", "SHUTDOWN_DRAIN": drain.String(),
	})
	base := "http://" + rs.addrs["main"]
	if got := get(t, base+"/readyz", nil); got != 200 {
		t.Fatalf("readyz = %d", got)
	}
	start := time.Now()
	rs.cancel()
	waitFor(t, func() bool { return get(t, base+"/readyz", nil) == 503 })
	if got := get(t, base+"/healthz", nil); got != 200 {
		t.Fatalf("must still serve during the drain, healthz = %d", got)
	}
	select {
	case err := <-rs.done:
		if err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took < drain {
			t.Fatalf("shut down after %v, before the %v drain ended", took, drain)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("shutdown timed out; logs:\n%s", rs.logs.String())
	}
}
