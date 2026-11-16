package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

func TestMetricsExposed(t *testing.T) {
	m := New("1.2.3", "abc")
	m.WatchCache(func() int { return 7 })
	m.WatchBanned(func(prefix string) int {
		if prefix == "ip:" {
			return 2
		}
		return 1
	})
	m.Request("allowed", "cache")
	m.CacheLookup(true)
	m.CacheLookup(false)
	m.EntraCall("accepted", 0.2)
	m.EntraReject("AADSTS50126")
	m.EntraError("AADSTS7000215")
	m.Ban("ip:1.2.3.4")
	m.Ban("user:bob")
	m.Ban("weird")

	out := scrape(t, m)
	for _, want := range []string{
		`entra_forward_auth_requests_total{reason="cache",result="allowed"} 1`,
		`entra_forward_auth_cache_lookups_total{result="hit"} 1`,
		`entra_forward_auth_cache_lookups_total{result="miss"} 1`,
		`entra_forward_auth_cache_entries 7`,
		`entra_forward_auth_entra_request_duration_seconds_count{outcome="accepted"} 1`,
		`entra_forward_auth_entra_rejects_total{code="AADSTS50126"} 1`,
		`entra_forward_auth_entra_errors_total{code="AADSTS7000215"} 1`,
		`entra_forward_auth_bans_total{kind="ip"} 1`,
		`entra_forward_auth_bans_total{kind="user"} 1`,
		`entra_forward_auth_bans_total{kind="other"} 1`,
		`entra_forward_auth_banned_keys{kind="ip"} 2`,
		`entra_forward_auth_banned_keys{kind="user"} 1`,
		`entra_forward_auth_build_info{goversion="go`,
		`version="1.2.3"`,
		`revision="abc"`,
		`go_goroutines`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output", want)
		}
	}
	if m.Registry() == nil {
		t.Fatal("nil registry")
	}
}

func TestIndependentRegistries(t *testing.T) {
	a, b := New("v", "r"), New("v", "r") // must not panic on duplicate registration
	a.Request("denied", "banned")
	if strings.Contains(scrape(t, b), `reason="banned"`) {
		t.Fatal("registries share state")
	}
}
