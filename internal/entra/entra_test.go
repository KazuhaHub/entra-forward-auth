package entra

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/entra-forward-auth/internal/credential"
)

type testSigner struct {
	signer *credential.Credential
	pub    *rsa.PublicKey
}

func (s testSigner) Assertion(clientID, audience string) (string, error) {
	return s.signer.Assertion(clientID, audience, time.Now())
}

var (
	sharedSignerOnce sync.Once
	sharedSigner     testSigner
)

// newTestSigner returns a process-wide signer; RSA key generation is slow.
func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	sharedSignerOnce.Do(func() { sharedSigner = generateSigner(t) })
	return sharedSigner
}

func generateSigner(t *testing.T) testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := credential.Parse(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{signer: cred, pub: &key.PublicKey}
}

// fakeEntra is a token endpoint whose response is set per test.
type fakeEntra struct {
	*httptest.Server
	mu      sync.Mutex
	handler http.HandlerFunc
	forms   []url.Values
	paths   []string
}

func newFakeEntra(t *testing.T, h http.HandlerFunc) *fakeEntra {
	t.Helper()
	f := &fakeEntra{handler: h}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		f.handler(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func jsonResp(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func fakeJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	hdr := enc.EncodeToString([]byte(`{"alg":"RS256"}`))
	body, _ := json.Marshal(claims)
	return hdr + "." + enc.EncodeToString(body) + "." + enc.EncodeToString([]byte("sig"))
}

func tokenBody(t *testing.T, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"token_type": "Bearer", "access_token": fakeJWT(claims)})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newClient(t *testing.T, f *fakeEntra, mod func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		Authority: f.URL,
		TenantID:  "tenant-1",
		ClientID:  "client-1",
		Scope:     "api://client-1/Access",
		Signer:    newTestSigner(t),
		Timeout:   2 * time.Second,
	}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAcceptAndRequestShape(t *testing.T) {
	f := newFakeEntra(t, jsonResp(200, `{"token_type":"Bearer","access_token":"opaque"}`))
	signer := newTestSigner(t)
	c := newClient(t, f, func(cfg *Config) { cfg.Signer = signer })

	res, err := c.Authenticate(context.Background(), "alice@example.com", "p&ss w=rd")
	if err != nil || res.Verdict != Accepted {
		t.Fatalf("got %+v, %v", res, err)
	}
	if len(f.forms) != 1 {
		t.Fatalf("calls = %d", len(f.forms))
	}
	if f.paths[0] != "POST /tenant-1/oauth2/v2.0/token" {
		t.Fatalf("request = %q", f.paths[0])
	}
	form := f.forms[0]
	want := map[string]string{
		"grant_type":            "password",
		"client_id":             "client-1",
		"scope":                 "api://client-1/Access",
		"username":              "alice@example.com",
		"password":              "p&ss w=rd",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("form[%s] = %q, want %q", k, form.Get(k), v)
		}
	}
	if form.Has("client_secret") {
		t.Error("client_secret must not be sent with an assertion")
	}

	// The assertion must verify with the key and address this very endpoint.
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Fatalf("assertion not a JWT: %q", form.Get("client_assertion"))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(signer.pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("assertion signature invalid: %v", err)
	}
	var claims struct{ Aud, Iss, Sub string }
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &claims)
	if claims.Aud != c.Endpoint() || claims.Aud != f.URL+"/tenant-1/oauth2/v2.0/token" {
		t.Errorf("aud = %q, endpoint = %q", claims.Aud, c.Endpoint())
	}
	if claims.Iss != "client-1" || claims.Sub != "client-1" {
		t.Errorf("iss/sub = %q/%q", claims.Iss, claims.Sub)
	}
}

func TestClientSecretVariant(t *testing.T) {
	f := newFakeEntra(t, jsonResp(200, `{"access_token":"x"}`))
	c := newClient(t, f, func(cfg *Config) { cfg.Signer = nil; cfg.ClientSecret = "s3cret" })
	if res, err := c.Authenticate(context.Background(), "u", "p"); err != nil || res.Verdict != Accepted {
		t.Fatalf("got %+v, %v", res, err)
	}
	form := f.forms[0]
	if form.Get("client_secret") != "s3cret" || form.Has("client_assertion") || form.Has("client_assertion_type") {
		t.Fatalf("unexpected form: %v", form)
	}
}

func TestRejected(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantCode   string
		wantMetric string
	}{
		{"invalid password", 400, `{"error":"invalid_grant","error_codes":[50126,1],"error_description":"AADSTS50126: Error validating credentials"}`, "AADSTS50126", "AADSTS50126"},
		{"invalid_grant without codes", 400, `{"error":"invalid_grant"}`, "invalid_grant", "other"},
		{"mfa required", 400, `{"error":"interaction_required","error_codes":[50076]}`, "AADSTS50076", "AADSTS50076"},
		{"invalid_grant on 401", 401, `{"error":"invalid_grant","error_codes":[50034]}`, "AADSTS50034", "AADSTS50034"},
		{"invalid_grant on 403", 403, `{"error":"invalid_grant"}`, "invalid_grant", "other"},
		{"unknown error is a rejection", 400, `{"error":"something_new","error_codes":[12345]}`, "AADSTS12345", "AADSTS12345"},
		{"unknown error string only", 400, `{"error":"invalid_request"}`, "invalid_request", "other"},
		{"unauthorized no body", 401, ``, "HTTP 401", "other"},
		{"forbidden html", 403, `<html>nope</html>`, "HTTP 403", "other"},
		{"empty error", 400, `{"error":""}`, "HTTP 400", "other"},
		{"control chars stripped", 400, `{"error":"bad\nline\u0000x"}`, "badlinex", "other"},
		{"long error truncated", 400, `{"error":"` + strings.Repeat("é", 100) + `"}`, strings.Repeat("é", 32), "other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEntra(t, jsonResp(tc.status, tc.body))
			res, err := newClient(t, f, nil).Authenticate(context.Background(), "u", "p")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Verdict != Rejected || res.Code != tc.wantCode || res.MetricCode() != tc.wantMetric {
				t.Fatalf("got %+v metric=%q", res, res.MetricCode())
			}
		})
	}
}

// A known list of errors describes the service's own setup: unavailable,
// never a rejection.
func TestServiceErrors(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantCode   string
		wantMetric string
	}{
		{"invalid_client", 401, `{"error":"invalid_client","error_codes":[7000215]}`, "AADSTS7000215", "AADSTS7000215"},
		{"unauthorized_client", 400, `{"error":"unauthorized_client","error_codes":[700016]}`, "AADSTS700016", "AADSTS700016"},
		{"tenant not found", 400, `{"error":"invalid_request","error_codes":[90002]}`, "AADSTS90002", "AADSTS90002"},
		{"invalid_scope", 400, `{"error":"invalid_scope","error_codes":[70011]}`, "AADSTS70011", "AADSTS70011"},
		{"consent code 65001", 400, `{"error":"consent_required","error_codes":[65001]}`, "AADSTS65001", "AADSTS65001"},
		{"resource not found", 400, `{"error":"invalid_resource","error_codes":[500011]}`, "AADSTS500011", "AADSTS500011"},
		{"unsupported_grant_type", 400, `{"error":"unsupported_grant_type"}`, "unsupported_grant_type", "other"},
		{"invalid_resource string only", 400, `{"error":"invalid_resource"}`, "invalid_resource", "other"},
		{"known code under another error string", 400, `{"error":"invalid_grant","error_codes":[700027]}`, "AADSTS700027", "AADSTS700027"},
		{"known code not first", 400, `{"error":"invalid_request","error_codes":[1,900144]}`, "AADSTS1", "AADSTS1"},
		{"7000222 expired secret", 401, `{"error":"invalid_client","error_codes":[7000222]}`, "AADSTS7000222", "AADSTS7000222"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEntra(t, jsonResp(tc.status, tc.body))
			_, err := newClient(t, f, nil).Authenticate(context.Background(), "u", "p")
			var se *ServiceError
			if !errors.As(err, &se) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want *ServiceError wrapping ErrUnavailable", err)
			}
			if se.Code != tc.wantCode || se.MetricCode() != tc.wantMetric {
				t.Fatalf("code=%q metric=%q", se.Code, se.MetricCode())
			}
			if se.Error() == "" {
				t.Fatal("empty message")
			}
		})
	}
}

func TestUnavailable(t *testing.T) {
	tests := []struct {
		name string
		h    http.HandlerFunc
		mod  func(*Config)
	}{
		{"429", jsonResp(429, `{"error":"throttled"}`), nil},
		{"500", jsonResp(500, `oops`), nil},
		{"503", jsonResp(503, ``), nil},
		{"404", jsonResp(404, ``), nil},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, nil},
		{"200 not json", jsonResp(200, `<html>`), nil},
		{"200 no token", jsonResp(200, `{"token_type":"Bearer"}`), nil},
		{"200 empty token", jsonResp(200, `{"access_token":""}`), nil},
		{"200 empty body", jsonResp(200, ``), nil},
		{"oversized body", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"access_token":"`))
			_, _ = w.Write([]byte(strings.Repeat("a", maxBody+10)))
			_, _ = w.Write([]byte(`"}`))
		}, nil},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}, func(c *Config) { c.Timeout = 100 * time.Millisecond }},
		{"connection dropped", func(w http.ResponseWriter, _ *http.Request) {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}, nil},
		{"roles required but token opaque", jsonResp(200, `{"access_token":"opaque"}`), func(c *Config) { c.RequiredRoles = []string{"r"} }},
		{"roles required but payload not base64", jsonResp(200, `{"access_token":"a.!!!.c"}`), func(c *Config) { c.RequiredRoles = []string{"r"} }},
		{"roles required but payload not json", jsonResp(200, `{"access_token":"a.bm90anNvbg.c"}`), func(c *Config) { c.RequiredRoles = []string{"r"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEntra(t, tc.h)
			_, err := newClient(t, f, tc.mod).Authenticate(context.Background(), "u", "p")
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
			if strings.Contains(err.Error(), "p&") || strings.Contains(err.Error(), "client_assertion") {
				t.Fatalf("error leaks request data: %v", err)
			}
		})
	}
}

func TestUnreachableServer(t *testing.T) {
	f := newFakeEntra(t, jsonResp(200, `{}`))
	c := newClient(t, f, nil)
	f.Close()
	if _, err := c.Authenticate(context.Background(), "u", "p"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	f := newFakeEntra(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c := newClient(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Authenticate(ctx, "u", "p"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

type failingSigner struct{}

func (failingSigner) Assertion(string, string) (string, error) { return "", errors.New("no key") }

func TestSignerFailure(t *testing.T) {
	f := newFakeEntra(t, jsonResp(200, `{"access_token":"x"}`))
	c := newClient(t, f, func(cfg *Config) { cfg.Signer = failingSigner{} })
	if _, err := c.Authenticate(context.Background(), "u", "p"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if len(f.forms) != 0 {
		t.Fatal("Entra must not be called when signing fails")
	}
}

func TestBadRequestURL(t *testing.T) {
	c, err := New(Config{Authority: "http://[::1", TenantID: "t", ClientID: "c", Scope: "s", ClientSecret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background(), "u", "p"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestGroupsAndRoles(t *testing.T) {
	const gid = "11111111-2222-3333-4444-555555555555"
	tests := []struct {
		name       string
		groups     []string
		roles      []string
		claims     map[string]any
		wantVerdct Verdict
		wantReason string
	}{
		{"group present", []string{gid}, nil, map[string]any{"groups": []string{"x", gid}}, Accepted, ""},
		{"group case-insensitive", []string{strings.ToUpper(gid)}, nil, map[string]any{"groups": []string{gid}}, Accepted, ""},
		{"any of several groups", []string{"nope", gid}, nil, map[string]any{"groups": []string{gid}}, Accepted, ""},
		{"group missing", []string{gid}, nil, map[string]any{"groups": []string{"other"}}, Forbidden, ReasonForbidden},
		{"no groups claim", []string{gid}, nil, map[string]any{}, Forbidden, ReasonForbidden},
		{"groups overage fails closed", []string{gid}, nil, map[string]any{"_claim_names": map[string]string{"groups": "src1"}, "_claim_sources": map[string]any{}}, Forbidden, ReasonGroupsOverage},
		{"role present", nil, []string{"Auth.User"}, map[string]any{"roles": []string{"Auth.User"}}, Accepted, ""},
		{"role is case-sensitive", nil, []string{"Auth.User"}, map[string]any{"roles": []string{"auth.user"}}, Forbidden, ReasonForbidden},
		{"role missing", nil, []string{"Auth.User"}, map[string]any{"roles": []string{"Other"}}, Forbidden, ReasonForbidden},
		{"both satisfied", []string{gid}, []string{"r"}, map[string]any{"groups": []string{gid}, "roles": []string{"r"}}, Accepted, ""},
		{"both required, role missing", []string{gid}, []string{"r"}, map[string]any{"groups": []string{gid}}, Forbidden, ReasonForbidden},
		{"overage on unrelated claim ignored", nil, []string{"r"}, map[string]any{"roles": []string{"r"}, "_claim_names": map[string]string{"groups": "s"}}, Accepted, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEntra(t, jsonResp(200, tokenBody(t, tc.claims)))
			c := newClient(t, f, func(cfg *Config) { cfg.RequiredGroups, cfg.RequiredRoles = tc.groups, tc.roles })
			res, err := c.Authenticate(context.Background(), "u", "p")
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != tc.wantVerdct || res.Reason != tc.wantReason {
				t.Fatalf("got %+v, want verdict %v reason %q", res, tc.wantVerdct, tc.wantReason)
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	ok := Config{Authority: "https://x", TenantID: "t", ClientID: "c", Scope: "s", ClientSecret: "z"}
	tests := []struct {
		name string
		mod  func(*Config)
	}{
		{"no authority", func(c *Config) { c.Authority = "" }},
		{"no tenant", func(c *Config) { c.TenantID = "" }},
		{"no client", func(c *Config) { c.ClientID = "" }},
		{"no scope", func(c *Config) { c.Scope = "" }},
		{"no credential", func(c *Config) { c.ClientSecret = "" }},
		{"two credentials", func(c *Config) { c.Signer = failingSigner{} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ok
			tc.mod(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	c, err := New(ok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint() != "https://x/t/oauth2/v2.0/token" || c.cfg.Timeout != 8*time.Second {
		t.Fatalf("defaults wrong: %q %v", c.Endpoint(), c.cfg.Timeout)
	}
	ok.Authority, ok.TenantID = "https://x/", "a b"
	c, _ = New(ok)
	if c.Endpoint() != "https://x/a%20b/oauth2/v2.0/token" {
		t.Fatalf("endpoint = %q", c.Endpoint())
	}
}

func TestDefaultHTTPClient(t *testing.T) {
	hc := newHTTPClient(3 * time.Second)
	tr := hc.Transport.(*http.Transport)
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatal("TLS 1.2 minimum not enforced")
	}
	if tr.Proxy == nil || hc.Timeout != 3*time.Second {
		t.Fatal("proxy/timeout not configured")
	}
	// http.ProxyFromEnvironment reads HTTPS_PROXY once per process, so only
	// the wiring can be checked here.
	if tr.ForceAttemptHTTP2 != true {
		t.Fatal("HTTP/2 should remain enabled")
	}
}

func TestMetricCode(t *testing.T) {
	tests := map[string]string{
		"AADSTS50126": "AADSTS50126",
		"AADSTS":      "other",
		"AADSTSabc":   "other",
		"AADSTS1x":    "other",
		"invalid":     "other",
		"":            "other",
	}
	for in, want := range tests {
		if got := (Result{Code: in}).MetricCode(); got != want {
			t.Errorf("MetricCode(%q) = %q, want %q", in, got, want)
		}
	}
}
