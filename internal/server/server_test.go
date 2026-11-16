package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/entra-forward-auth/internal/basicauth"
	"github.com/KazuhaHub/entra-forward-auth/internal/cache"
	"github.com/KazuhaHub/entra-forward-auth/internal/clientip"
	"github.com/KazuhaHub/entra-forward-auth/internal/entra"
	"github.com/KazuhaHub/entra-forward-auth/internal/metrics"
	"github.com/KazuhaHub/entra-forward-auth/internal/ratelimit"
)

// fakeEntra is an Authenticator with scriptable behaviour.
type fakeEntra struct {
	calls   atomic.Int64
	active  atomic.Int64
	maxSeen atomic.Int64
	// fn decides the answer; the default accepts password "good" and rejects
	// everything else with AADSTS50126.
	fn func(ctx context.Context, user, password string) (entra.Result, error)
}

func (f *fakeEntra) Authenticate(ctx context.Context, user, password string) (entra.Result, error) {
	f.calls.Add(1)
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		old := f.maxSeen.Load()
		if n <= old || f.maxSeen.CompareAndSwap(old, n) {
			break
		}
	}
	if f.fn != nil {
		return f.fn(ctx, user, password)
	}
	if password == "good" {
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	return entra.Result{Verdict: entra.Rejected, Code: "AADSTS50126"}, nil
}

type harness struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	entra   *fakeEntra
	metrics *metrics.Metrics
	logs    *bytes.Buffer
	cache   *cache.Cache
	limiter *ratelimit.Limiter
}

type opts struct {
	cfg        func(*Config)
	cacheTTL   time.Duration
	failLimit  int
	maxKeys    int
	noDefaults bool
}

func newHarness(t *testing.T, o opts) *harness {
	t.Helper()
	if !o.noDefaults {
		if o.cacheTTL == 0 {
			o.cacheTTL = time.Minute
		}
		if o.failLimit == 0 {
			o.failLimit = 100
		}
	}
	h := &harness{t: t, entra: &fakeEntra{}, logs: &bytes.Buffer{}}
	h.metrics = metrics.New("test", "rev")
	h.cache = cache.New(o.cacheTTL, 100, nil)
	h.limiter = ratelimit.New(ratelimit.Config{
		Limit: o.failLimit, Window: time.Minute, BanTime: time.Hour, MaxKeys: o.maxKeys, OnBan: h.metrics.Ban,
	})
	h.metrics.WatchCache(h.cache.Len)
	h.metrics.WatchBanned(h.limiter.CountBanned)

	cfg := Config{
		Authenticator:  h.entra,
		IPs:            clientip.New("X-Real-IP", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil, nil),
		Cache:          h.cache,
		Limiter:        h.limiter,
		Metrics:        h.metrics,
		Logger:         slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		MaxConcurrency: 4,
	}
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv, h.handler = srv, srv.Handler()
	return h
}

// do sends a request through the handler. A nil hdr map means no headers.
func (h *harness) do(method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:5555"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *harness) auth(user, pass, ip string) *httptest.ResponseRecorder {
	hdr := map[string]string{"Authorization": basicauth.Encode(user, pass)}
	if ip != "" {
		hdr["X-Real-IP"] = ip
	}
	return h.do("GET", "/auth", hdr)
}

func (h *harness) metricsText() string {
	return h.do("GET", "/metrics", nil).Body.String()
}

func (h *harness) wantMetric(line string) {
	h.t.Helper()
	if !strings.Contains(h.metricsText(), line) {
		h.t.Fatalf("metrics missing %q", line)
	}
}

func TestAllowed(t *testing.T) {
	h := newHarness(t, opts{})
	rec := h.auth("  Alice@Example.COM ", "good", "203.0.113.1")
	if rec.Code != 204 {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-User"); got != "alice@example.com" {
		t.Fatalf("X-Auth-User = %q", got)
	}
	if rec.Body.Len() != 0 {
		t.Fatal("body must be empty")
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("no realm configured, no challenge expected")
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="entra",result="allowed"} 1`)
	h.wantMetric(`entra_forward_auth_entra_request_duration_seconds_count{outcome="accepted"} 1`)
}

func TestAnyMethodAndBodyNotRead(t *testing.T) {
	h := newHarness(t, opts{})
	for _, m := range []string{"GET", "POST", "PUT", "HEAD", "DELETE"} {
		req := httptest.NewRequest(m, "/auth", io.NopCloser(&panicReader{}))
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set("Authorization", basicauth.Encode("u@example.com", "good"))
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Errorf("%s: status %d", m, rec.Code)
		}
	}
}

type panicReader struct{}

func (*panicReader) Read([]byte) (int, error) { panic("request body must not be read") }

func TestUnauthorizedCases(t *testing.T) {
	tests := []struct {
		name   string
		hdr    map[string]string
		reason string
	}{
		{"no header", nil, "no_credentials"},
		{"bearer scheme", map[string]string{"Authorization": "Bearer abc"}, "malformed"},
		{"bad base64", map[string]string{"Authorization": "Basic %%%"}, "malformed"},
		{"empty password", map[string]string{"Authorization": basicauth.Encode("u", "x")[:6] + base64.StdEncoding.EncodeToString([]byte("u:"))}, "malformed"},
		{"blank user after trim", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("  :pw"))}, "malformed"},
		{"wrong password", map[string]string{"Authorization": basicauth.Encode("u@example.com", "bad")}, "rejected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, opts{})
			rec := h.do("GET", "/auth", tc.hdr)
			if rec.Code != 401 {
				t.Fatalf("status = %d", rec.Code)
			}
			if rec.Header().Get("X-Auth-User") != "" {
				t.Fatal("X-Auth-User must only be set on success")
			}
			h.wantMetric(fmt.Sprintf(`entra_forward_auth_requests_total{reason=%q,result="denied"} 1`, tc.reason))
		})
	}
}

func TestRejectedMetricsAndLogs(t *testing.T) {
	h := newHarness(t, opts{})
	h.auth("u@example.com", "bad", "203.0.113.1")
	h.wantMetric(`entra_forward_auth_entra_rejects_total{code="AADSTS50126"} 1`)
	h.wantMetric(`entra_forward_auth_entra_request_duration_seconds_count{outcome="rejected"} 1`)
	for _, want := range []string{"reason=rejected", "code=AADSTS50126", "ip=203.0.113.1", "user=u@example.com", "outcome=denied"} {
		if !strings.Contains(h.logs.String(), want) {
			t.Errorf("log missing %q:\n%s", want, h.logs.String())
		}
	}
}

func TestCredentialsNeverLogged(t *testing.T) {
	h := newHarness(t, opts{})
	h.entra.fn = func(_ context.Context, _, pw string) (entra.Result, error) {
		if pw == "unavail-secret-pw" {
			return entra.Result{}, fmt.Errorf("%w: connection refused", entra.ErrUnavailable)
		}
		return entra.Result{Verdict: entra.Rejected, Code: "AADSTS50126"}, nil
	}
	for _, pw := range []string{"s3cret-pw-1", "unavail-secret-pw"} {
		h.auth("u@example.com", pw, "")
	}
	h.auth("u@example.com", "s3cret-pw-1", "")
	hdr := basicauth.Encode("u@example.com", "s3cret-pw-1")
	for _, forbidden := range []string{"s3cret-pw-1", "unavail-secret-pw", hdr, strings.TrimPrefix(hdr, "Basic "), "Authorization"} {
		if strings.Contains(h.logs.String(), forbidden) || strings.Contains(h.metricsText(), forbidden) {
			t.Fatalf("output leaks %q", forbidden)
		}
	}
}

func TestMalformedNotCountedAsFailure(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2})
	for range 10 {
		h.do("GET", "/auth", map[string]string{"X-Real-IP": "203.0.113.9"})
		h.do("GET", "/auth", map[string]string{"X-Real-IP": "203.0.113.9", "Authorization": "Basic !!"})
	}
	if h.limiter.Len() != 0 {
		t.Fatalf("limiter tracked %d keys; no-credential requests must not count", h.limiter.Len())
	}
	if rec := h.auth("u@example.com", "good", "203.0.113.9"); rec.Code != 204 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestForbiddenAndOverage(t *testing.T) {
	for _, reason := range []string{entra.ReasonForbidden, entra.ReasonGroupsOverage} {
		t.Run(reason, func(t *testing.T) {
			h := newHarness(t, opts{})
			h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
				return entra.Result{Verdict: entra.Forbidden, Reason: reason}, nil
			}
			for range 2 { // second request proves it was not cached
				if rec := h.auth("u@example.com", "good", ""); rec.Code != 401 {
					t.Fatalf("status = %d", rec.Code)
				}
			}
			if h.entra.calls.Load() != 2 {
				t.Fatalf("entra calls = %d; forbidden must not be cached", h.entra.calls.Load())
			}
			h.wantMetric(fmt.Sprintf(`entra_forward_auth_requests_total{reason=%q,result="denied"} 2`, reason))
			h.wantMetric(`entra_forward_auth_entra_request_duration_seconds_count{outcome="accepted"} 2`)
			if h.limiter.Len() == 0 {
				t.Fatal("forbidden must count as a failure")
			}
		})
	}
}

func TestUnavailable(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		return entra.Result{}, fmt.Errorf("%w: boom", entra.ErrUnavailable)
	}
	for range 3 {
		if rec := h.auth("u@example.com", "good", "203.0.113.5"); rec.Code != 503 {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}
	if h.limiter.Len() != 0 {
		t.Fatal("unavailable must not count as a failure (FAIL_LIMIT=1 would have banned)")
	}
	if h.cache.Len() != 0 {
		t.Fatal("unavailable must not be cached")
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="unavailable",result="unavailable"} 3`)
	h.wantMetric(`entra_forward_auth_entra_request_duration_seconds_count{outcome="unavailable"} 3`)

	// Recovery: Entra comes back and the same user gets in.
	h.entra.fn = nil
	if rec := h.auth("u@example.com", "good", "203.0.113.5"); rec.Code != 204 {
		t.Fatalf("status = %d after recovery", rec.Code)
	}
}

func TestBannedShortCircuit(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2})
	for range 2 {
		if rec := h.auth("victim@example.com", "bad", "203.0.113.1"); rec.Code != 401 {
			t.Fatal("expected 401")
		}
	}
	callsBefore := h.entra.calls.Load()

	// Same IP, other user, even with the right password: banned by IP.
	if rec := h.auth("other@example.com", "good", "203.0.113.1"); rec.Code != 401 {
		t.Fatalf("ip ban: status = %d", rec.Code)
	}
	// Same user from a different IP, right password: banned by user.
	if rec := h.auth("victim@example.com", "good", "198.51.100.77"); rec.Code != 401 {
		t.Fatalf("user ban: status = %d", rec.Code)
	}
	// Unrelated IP and user are unaffected.
	if rec := h.auth("other@example.com", "good", "198.51.100.77"); rec.Code != 204 {
		t.Fatalf("unrelated: status = %d", rec.Code)
	}
	if got := h.entra.calls.Load() - callsBefore; got != 1 {
		t.Fatalf("Entra called %d times after the ban, want 1 (only the unrelated request)", got)
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="banned",result="denied"} 2`)
	h.wantMetric(`entra_forward_auth_bans_total{kind="ip"} 1`)
	h.wantMetric(`entra_forward_auth_bans_total{kind="user"} 1`)
	h.wantMetric(`entra_forward_auth_banned_keys{kind="ip"} 1`)
	h.wantMetric(`entra_forward_auth_banned_keys{kind="user"} 1`)
}

func TestSuccessDoesNotResetFailures(t *testing.T) {
	h := newHarness(t, opts{failLimit: 3})
	h.auth("a@example.com", "bad", "203.0.113.1")
	h.auth("b@example.com", "bad", "203.0.113.1")
	h.auth("c@example.com", "good", "203.0.113.1") // success in between
	h.auth("d@example.com", "bad", "203.0.113.1")  // third failure from this IP
	if rec := h.auth("e@example.com", "good", "203.0.113.1"); rec.Code != 401 {
		t.Fatalf("status = %d; IP should be banned", rec.Code)
	}
}

func TestRateLimitDisabled(t *testing.T) {
	h := newHarness(t, opts{noDefaults: true, cacheTTL: time.Minute})
	for range 20 {
		h.auth("u@example.com", "bad", "203.0.113.1")
	}
	if rec := h.auth("u@example.com", "good", "203.0.113.1"); rec.Code != 204 {
		t.Fatalf("status = %d; FAIL_LIMIT=0 must never ban", rec.Code)
	}
}

func TestCacheHit(t *testing.T) {
	h := newHarness(t, opts{})
	for i := range 3 {
		if rec := h.auth("u@example.com", "good", ""); rec.Code != 204 {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
	}
	if got := h.entra.calls.Load(); got != 1 {
		t.Fatalf("Entra called %d times, want 1", got)
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="cache",result="allowed"} 2`)
	h.wantMetric(`entra_forward_auth_cache_lookups_total{result="hit"} 2`)
	h.wantMetric(`entra_forward_auth_cache_lookups_total{result="miss"} 1`)
	h.wantMetric(`entra_forward_auth_cache_entries 1`)

	// A different password for the same user is a different cache key.
	if rec := h.auth("u@example.com", "bad", ""); rec.Code != 401 {
		t.Fatal("wrong password must not be served from cache")
	}
	// And so is the same password for a different user.
	if rec := h.auth("v@example.com", "good", ""); rec.Code != 204 || h.entra.calls.Load() != 3 {
		t.Fatalf("status %d calls %d", rec.Code, h.entra.calls.Load())
	}
}

func TestCacheDisabled(t *testing.T) {
	h := newHarness(t, opts{failLimit: 100, cfg: func(c *Config) { c.Cache = cache.New(0, 10, nil) }})
	for range 3 {
		h.auth("u@example.com", "good", "")
	}
	if got := h.entra.calls.Load(); got != 3 {
		t.Fatalf("Entra called %d times, want 3 with CACHE_TTL=0", got)
	}
}

func TestSingleflight(t *testing.T) {
	const n = 25
	h := newHarness(t, opts{})
	release := make(chan struct{})
	started := make(chan struct{}, n)
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		started <- struct{}{}
		<-release
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	ts := httptest.NewServer(h.handler)
	defer ts.Close()

	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", ts.URL+"/auth", nil)
			req.Header.Set("Authorization", basicauth.Encode("u@example.com", "good"))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	<-started                          // the leader is in Entra
	time.Sleep(150 * time.Millisecond) // let the others pile up behind it
	close(release)
	wg.Wait()

	for i, c := range codes {
		if c != 204 {
			t.Fatalf("request %d: status %d", i, c)
		}
	}
	if got := h.entra.calls.Load(); got != 1 {
		t.Fatalf("Entra called %d times for %d identical parallel requests, want 1", got, n)
	}
}

func TestSingleflightSharesRejection(t *testing.T) {
	h := newHarness(t, opts{})
	release := make(chan struct{})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		<-release
		return entra.Result{Verdict: entra.Rejected, Code: "AADSTS50126"}, nil
	}
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = h.auth("u@example.com", "bad", "").Code }()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()
	for _, c := range codes {
		if c != 401 {
			t.Fatalf("codes = %v", codes)
		}
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="rejected",result="denied"} 8`)
}

func TestConcurrencyBound(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.MaxConcurrency = 2 }}) // up to 8 flights
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		time.Sleep(20 * time.Millisecond)
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); h.auth(fmt.Sprintf("user%d@example.com", i), "good", "") }()
	}
	wg.Wait()
	if got := h.entra.calls.Load(); got != 8 {
		t.Fatalf("calls = %d", got)
	}
	if got := h.entra.maxSeen.Load(); got > 2 {
		t.Fatalf("saw %d concurrent Entra calls, bound is 2", got)
	}
}

func TestCancelledRequestDoesNotCancelSharedCall(t *testing.T) {
	h := newHarness(t, opts{})
	release := make(chan struct{})
	var ctxErr atomic.Value
	h.entra.fn = func(ctx context.Context, _, _ string) (entra.Result, error) {
		<-release
		ctxErr.Store(fmt.Sprint(ctx.Err()))
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/auth", nil).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Authorization", basicauth.Encode("u@example.com", "good"))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.handler.ServeHTTP(rec, req); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel() // the first client goes away while Entra is still thinking
	<-done
	if rec.Code != 503 {
		t.Fatalf("status = %d for the abandoned request", rec.Code)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for ctxErr.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ctxErr.Load(); got != "<nil>" {
		t.Fatalf("shared call context error = %v, want <nil>", got)
	}
	// The abandoned call still populated the cache.
	deadline = time.Now().Add(2 * time.Second)
	for h.cache.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if rec := h.auth("u@example.com", "good", ""); rec.Code != 204 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDomainAllowList(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.AllowedDomains = []string{"@example.com", "@corp.example"} }})
	tests := []struct {
		user string
		want int
	}{
		{"alice@example.com", 204},
		{"ALICE@EXAMPLE.COM", 204},
		{"bob@corp.example", 204},
		{"mallory@evil.com", 401},
		{"mallory@example.com.evil.com", 401},
		{"example.com", 401},
	}
	for _, tc := range tests {
		if rec := h.auth(tc.user, "good", ""); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.user, rec.Code, tc.want)
		}
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="domain",result="denied"} 3`)
	// alice (twice, normalised to one cache key) and bob: two calls; the
	// domain rejects never reach Entra.
	if got := h.entra.calls.Load(); got != 2 {
		t.Fatalf("Entra called %d times; domain rejects must not reach it", got)
	}
}

func TestDomainRejectCountsAsFailure(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2, cfg: func(c *Config) { c.AllowedDomains = []string{"@example.com"} }})
	h.auth("a@evil.com", "x", "203.0.113.1")
	h.auth("b@evil.com", "x", "203.0.113.1")
	if rec := h.auth("c@example.com", "good", "203.0.113.1"); rec.Code != 401 {
		t.Fatalf("status = %d; IP should be banned after two domain failures", rec.Code)
	}
}

func TestRealmHeader(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.Realm = `My "App"` }})
	rec := h.do("GET", "/auth", nil)
	want := `Basic realm="My \"App\"", charset="UTF-8"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
	if rec := h.auth("u@example.com", "good", ""); rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("no challenge on success")
	}
	if rec := h.auth("u@example.com", "bad", ""); rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("challenge expected on rejection")
	}
	// 503 carries no challenge.
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		return entra.Result{}, entra.ErrUnavailable
	}
	if rec := h.auth("z@example.com", "good", ""); rec.Code != 503 || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("503 response wrong: %d %v", rec.Code, rec.Header())
	}
}

func TestClientIPHeaderHonouredOnlyFromTrustedPeer(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1})
	// Untrusted peer spoofing X-Real-IP: the ban lands on the real peer.
	req := httptest.NewRequest("GET", "/auth", nil)
	req.RemoteAddr = "198.51.100.50:9"
	req.Header.Set("X-Real-IP", "203.0.113.200")
	req.Header.Set("Authorization", basicauth.Encode("u@example.com", "bad"))
	h.handler.ServeHTTP(httptest.NewRecorder(), req)
	if !h.limiter.Banned("ip:198.51.100.50") || h.limiter.Banned("ip:203.0.113.200") {
		t.Fatal("ban must use the peer address when the peer is untrusted")
	}
}

func TestHealthAndReadiness(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	h := newHarness(t, opts{cfg: func(c *Config) { c.Ready = ready.Load }})

	if rec := h.do("GET", "/healthz", nil); rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
	if rec := h.do("GET", "/readyz", nil); rec.Code != 200 {
		t.Fatalf("readyz = %d", rec.Code)
	}
	ready.Store(false)
	if rec := h.do("GET", "/readyz", nil); rec.Code != 503 {
		t.Fatalf("readyz without credential = %d", rec.Code)
	}
	ready.Store(true)
	h.srv.SetShuttingDown()
	if rec := h.do("GET", "/readyz", nil); rec.Code != 503 {
		t.Fatalf("readyz during shutdown = %d", rec.Code)
	}
	if rec := h.do("GET", "/healthz", nil); rec.Code != 200 {
		t.Fatal("healthz must stay 200 while draining")
	}
}

func TestNilReadyMeansReady(t *testing.T) {
	h := newHarness(t, opts{})
	if rec := h.do("GET", "/readyz", nil); rec.Code != 200 {
		t.Fatalf("readyz = %d", rec.Code)
	}
}

func TestUnknownPaths(t *testing.T) {
	h := newHarness(t, opts{})
	for _, p := range []string{"/", "/auth/x", "/nope", "/healthz/x"} {
		if rec := h.do("GET", p, nil); rec.Code != 404 {
			t.Errorf("%s: status %d, want 404", p, rec.Code)
		}
	}
}

func TestMetricsEndpoints(t *testing.T) {
	h := newHarness(t, opts{})
	h.auth("u@example.com", "good", "")
	out := h.metricsText()
	for _, want := range []string{"entra_forward_auth_requests_total", "entra_forward_auth_build_info", "go_goroutines", "process_"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	sep := newHarness(t, opts{cfg: func(c *Config) { c.SeparateMetrics = true }})
	if rec := sep.do("GET", "/metrics", nil); rec.Code != 404 {
		t.Fatalf("main handler must not serve /metrics when separate, got %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	sep.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "entra_forward_auth_build_info") {
		t.Fatalf("metrics listener: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	sep.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/auth", nil))
	if rec.Code != 404 {
		t.Fatalf("metrics listener must not serve /auth, got %d", rec.Code)
	}
}

func TestNewHTTPServer(t *testing.T) {
	s := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), 8*time.Second)
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second ||
		s.WriteTimeout != 13*time.Second || s.IdleTimeout != 60*time.Second || s.MaxHeaderBytes != 16<<10 {
		t.Fatalf("timeouts wrong: %+v", s)
	}
}

func TestNewDefaults(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.MaxConcurrency = 0; c.Logger = nil; c.Now = nil }})
	if cap(h.srv.sem) != 16 {
		t.Fatalf("default concurrency = %d", cap(h.srv.sem))
	}
	if rec := h.auth("u@example.com", "good", ""); rec.Code != 204 {
		t.Fatal("server with defaults failed")
	}
}

func TestClip(t *testing.T) {
	if got := clip(strings.Repeat("a", 500)); len(got) != 128 {
		t.Fatalf("len = %d", len(got))
	}
	if clip("short") != "short" {
		t.Fatal("short strings unchanged")
	}
}

func TestFlightGroupWaiterCancellation(t *testing.T) {
	var g flightGroup
	release := make(chan struct{})
	started := make(chan struct{})
	var runs atomic.Int32
	fn := func(context.Context) attemptResult {
		runs.Add(1)
		close(started)
		<-release
		return attemptResult{res: entra.Result{Verdict: entra.Accepted}}
	}
	leaderDone := make(chan error, 1)
	go func() {
		_, err := g.do(context.Background(), cache.Key{1}, fn)
		leaderDone <- err
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.do(ctx, cache.Key{1}, fn); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 1 {
		t.Fatalf("fn ran %d times", runs.Load())
	}
	// After completion the key is free again.
	if res, err := g.do(context.Background(), cache.Key{1}, func(context.Context) attemptResult {
		return attemptResult{res: entra.Result{Verdict: entra.Rejected}}
	}); err != nil || res.res.Verdict != entra.Rejected {
		t.Fatalf("second flight: %+v %v", res, err)
	}
}

func TestFlightGroupOverload(t *testing.T) {
	g := flightGroup{max: 1}
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_, _ = g.do(context.Background(), cache.Key{1}, func(context.Context) attemptResult {
			close(started)
			<-release
			return attemptResult{}
		})
	}()
	<-started
	if _, err := g.do(context.Background(), cache.Key{2}, func(context.Context) attemptResult {
		t.Error("must not run")
		return attemptResult{}
	}); !errors.Is(err, errOverloaded) {
		t.Fatalf("err = %v, want errOverloaded", err)
	}
	close(release)
}

func TestEndToEndWithEntraClient(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("password") == "good" && r.PostForm.Get("client_secret") == "shh" {
			_, _ = w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_codes":[50126]}`))
	}))
	defer ts.Close()

	client, err := entra.New(entra.Config{Authority: ts.URL, TenantID: "t", ClientID: "c", Scope: "s", ClientSecret: "shh", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, opts{cfg: func(c *Config) { c.Authenticator = client }})
	if rec := h.auth("u@example.com", "good", ""); rec.Code != 204 {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec := h.auth("u@example.com", "wrong", ""); rec.Code != 401 {
		t.Fatalf("status = %d", rec.Code)
	}
	ts.Close()
	if rec := h.auth("new@example.com", "good", ""); rec.Code != 503 {
		t.Fatalf("status = %d with Entra down, want 503", rec.Code)
	}
	if rec := h.auth("u@example.com", "good", ""); rec.Code != 204 {
		t.Fatal("cached user should still pass while Entra is down")
	}
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *harness) inFlight() int {
	h.srv.flights.mu.Lock()
	defer h.srv.flights.mu.Unlock()
	return len(h.srv.flights.calls)
}

func TestParallelGuessesBoundedByFailLimit(t *testing.T) {
	h := newHarness(t, opts{failLimit: 3})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		time.Sleep(50 * time.Millisecond)
		return entra.Result{Verdict: entra.Rejected, Code: "AADSTS50126"}, nil
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() { defer wg.Done(); h.auth("victim@example.com", fmt.Sprintf("guess-%d", i), "203.0.113.1") }()
	}
	wg.Wait()
	if got := h.entra.calls.Load(); got > 3 {
		t.Fatalf("%d guesses reached Entra with FAIL_LIMIT=3", got)
	}
	if rec := h.auth("victim@example.com", "good", "198.51.100.2"); rec.Code != 401 {
		t.Fatalf("victim must be locked out, got %d", rec.Code)
	}
	out := h.metricsText()
	if !strings.Contains(out, `reason="throttled"`) && !strings.Contains(out, `reason="banned"`) {
		t.Fatal("expected throttled or banned refusals")
	}
}

func TestThrottledReason(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2})
	release := make(chan struct{})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		<-release
		return entra.Result{Verdict: entra.Rejected}, nil
	}
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); h.auth("u@example.com", fmt.Sprintf("g%d", i), "203.0.113.1") }()
	}
	waitUntil(t, "two attempts in flight", func() bool { return h.inFlight() == 2 })
	rec := h.auth("u@example.com", "g3", "203.0.113.1")
	if rec.Code != 401 {
		t.Fatalf("status = %d", rec.Code)
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="throttled",result="denied"} 1`)
	close(release)
	wg.Wait()
}

// A client that disconnects before Entra answers must not buy free guesses.
func TestClientCancelStillCounted(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1})
	release := make(chan struct{})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		<-release
		return entra.Result{Verdict: entra.Rejected, Code: "AADSTS50126"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/auth", nil).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Real-IP", "203.0.113.1")
	req.Header.Set("Authorization", basicauth.Encode("victim@example.com", "wrong"))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.handler.ServeHTTP(rec, req); close(done) }()
	waitUntil(t, "attempt in flight", func() bool { return h.inFlight() == 1 })
	cancel()
	<-done
	if rec.Code != 503 {
		t.Fatalf("abandoned request status = %d", rec.Code)
	}
	close(release)
	waitUntil(t, "ban to be recorded", func() bool { return h.limiter.Banned("user:victim@example.com") })
	if rec := h.auth("victim@example.com", "good", "198.51.100.9"); rec.Code != 401 {
		t.Fatalf("status = %d; the abandoned guess must have counted", rec.Code)
	}
	h.wantMetric(`entra_forward_auth_entra_rejects_total{code="AADSTS50126"} 1`)
}

func TestBannedBeatsCache(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1})
	if rec := h.auth("u@example.com", "good", "203.0.113.1"); rec.Code != 204 {
		t.Fatalf("status = %d", rec.Code)
	}
	h.auth("u@example.com", "bad", "203.0.113.2") // bans the user
	if rec := h.auth("u@example.com", "good", "203.0.113.3"); rec.Code != 401 {
		t.Fatalf("cached password must not bypass a ban, got %d", rec.Code)
	}
}

func TestOverloadedWhenTooManyFlights(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.MaxConcurrency = 1 }}) // 4 flights max
	release := make(chan struct{})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		<-release
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); h.auth(fmt.Sprintf("u%d@example.com", i), "good", "") }()
	}
	waitUntil(t, "four flights", func() bool { return h.inFlight() == 4 })
	rec := h.auth("u5@example.com", "good", "")
	if rec.Code != 503 {
		t.Fatalf("status = %d, want immediate 503", rec.Code)
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="overloaded",result="unavailable"} 1`)
	close(release)
	wg.Wait()
	if got := h.entra.calls.Load(); got != 4 {
		t.Fatalf("calls = %d; the overloaded request must not reach Entra", got)
	}
}

func TestSlotWaitHonoursFlightTimeout(t *testing.T) {
	h := newHarness(t, opts{cfg: func(c *Config) { c.MaxConcurrency = 1; c.EntraTimeout = 100 * time.Millisecond }})
	release := make(chan struct{})
	defer close(release)
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		<-release // holds the only call slot
		return entra.Result{}, fmt.Errorf("%w: slow", entra.ErrUnavailable)
	}
	go h.auth("slow@example.com", "good", "")
	waitUntil(t, "first call", func() bool { return h.entra.calls.Load() == 1 })
	start := time.Now()
	rec := h.auth("waiter@example.com", "good", "")
	if rec.Code != 503 || time.Since(start) > 2*time.Second {
		t.Fatalf("status %d after %v; the slot wait must end with the flight timeout", rec.Code, time.Since(start))
	}
	if got := h.entra.calls.Load(); got != 1 {
		t.Fatalf("calls = %d; the waiter must never reach Entra", got)
	}
}

func TestServiceMisconfigurationIsUnavailable(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1})
	h.entra.fn = func(context.Context, string, string) (entra.Result, error) {
		return entra.Result{}, &entra.ServiceError{Code: "AADSTS7000215"}
	}
	for range 3 {
		if rec := h.auth("u@example.com", "good", "203.0.113.1"); rec.Code != 503 {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	if h.limiter.Len() != 0 || h.cache.Len() != 0 {
		t.Fatal("misconfiguration must not count as a failure or be cached")
	}
	h.wantMetric(`entra_forward_auth_entra_errors_total{code="AADSTS7000215"} 3`)
	if !strings.Contains(h.logs.String(), "level=ERROR") || !strings.Contains(h.logs.String(), "code=AADSTS7000215") {
		t.Fatalf("expected an ERROR log with the code:\n%s", h.logs.String())
	}
	if strings.Contains(h.metricsText(), "entra_rejects_total{") {
		t.Fatal("not a user rejection")
	}
}

func TestIPv6KeyedByPrefix(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2})
	h.auth("a@example.com", "bad", "2001:db8:1:2::1")
	h.auth("b@example.com", "bad", "2001:db8:1:2:ffff::9") // same /64
	if !h.limiter.Banned("ip:2001:db8:1:2::/64") {
		t.Fatal("the /64 should be banned")
	}
	if rec := h.auth("c@example.com", "good", "2001:db8:1:2::77"); rec.Code != 401 {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec := h.auth("c@example.com", "good", "2001:db8:1:3::1"); rec.Code != 204 {
		t.Fatalf("a different /64 is unaffected, got %d", rec.Code)
	}
	if limiterIPKey(netip.MustParseAddr("192.0.2.7")) != "ip:192.0.2.7" {
		t.Fatal("IPv4 keyed by address")
	}
}

func TestDomainRejectsCreateNoUserKeys(t *testing.T) {
	h := newHarness(t, opts{failLimit: 100, cfg: func(c *Config) { c.AllowedDomains = []string{"@example.com"} }})
	for i := range 20 {
		h.auth(fmt.Sprintf("x%d@evil.com", i), "pw", "203.0.113.1")
	}
	if got := h.limiter.Len(); got != 1 {
		t.Fatalf("limiter tracks %d keys, want only the IP", got)
	}
}

func TestLimiterTableFullFailsClosed(t *testing.T) {
	h := newHarness(t, opts{failLimit: 1, maxKeys: 2})
	h.auth("a@example.com", "bad", "203.0.113.1") // bans ip + user: table full of bans
	for range 3 {
		if rec := h.auth("b@example.com", "good", "198.51.100.1"); rec.Code != 503 {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}
	h.wantMetric(`entra_forward_auth_requests_total{reason="overloaded",result="unavailable"} 3`)
	if n := strings.Count(h.logs.String(), "table is full"); n != 1 {
		t.Fatalf("full-table error logged %d times, want once per minute", n)
	}
}

func TestClipUTF8Boundary(t *testing.T) {
	in := strings.Repeat("a", 127) + "é" + "tail" // é occupies bytes 127-128
	got := clip(in)
	if len(got) != 127 || !utf8.ValidString(got) {
		t.Fatalf("clip = %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if got := clip(strings.Repeat("é", 200)); !utf8.ValidString(got) || len(got) > 128 {
		t.Fatalf("clip of multibyte text invalid: %d", len(got))
	}
}

func TestPanicInAttemptReleasesReservation(t *testing.T) {
	h := newHarness(t, opts{failLimit: 2})
	h.entra.fn = func(_ context.Context, _, pw string) (entra.Result, error) {
		if pw == "boom" {
			panic("secret-detail-boom")
		}
		return entra.Result{Verdict: entra.Accepted}, nil
	}
	for range 3 { // more than FAIL_LIMIT: leaked reservations would throttle
		if rec := h.auth("u@example.com", "boom", "203.0.113.1"); rec.Code != 503 {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}
	if h.limiter.Len() != 0 {
		t.Fatalf("limiter kept %d entries; reservation leaked", h.limiter.Len())
	}
	if !strings.Contains(h.logs.String(), "level=ERROR") || strings.Contains(h.logs.String(), "secret-detail-boom") {
		t.Fatalf("expected an ERROR log without the panic value:\n%s", h.logs.String())
	}
	if rec := h.auth("u@example.com", "good", "203.0.113.1"); rec.Code != 204 {
		t.Fatalf("service must keep working, got %d", rec.Code)
	}
	if h.inFlight() != 0 {
		t.Fatal("flight not cleaned up")
	}
}
