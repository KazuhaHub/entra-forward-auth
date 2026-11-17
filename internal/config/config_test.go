package config

import (
	"bytes"
	"errors"
	"flag"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{
		"ENTRA_TENANT_ID":   "tenant",
		"ENTRA_CLIENT_ID":   "client",
		"ENTRA_SCOPE":       "api://client/Access",
		"ENTRA_CLIENT_CERT": "/c.pem",
		"ENTRA_CLIENT_KEY":  "/k.pem",
	}
}

func load(t *testing.T, e map[string]string, args ...string) (*Config, error) {
	t.Helper()
	return Load(args, env(e), &bytes.Buffer{})
}

func TestDefaults(t *testing.T) {
	c, err := load(t, base())
	if err != nil {
		t.Fatal(err)
	}
	if c.Authority != "https://login.microsoftonline.com" || c.EntraTimeout != 8*time.Second ||
		c.EntraMaxConcurrency != 16 || c.Listen != "127.0.0.1:5002" || c.ClientIPHeader != "X-Real-IP" ||
		c.CacheTTL != 10*time.Minute || c.CacheMaxEntries != 10000 || c.FailWindow != 10*time.Minute ||
		c.FailLimit != 5 || c.BanTime != 15*time.Minute || c.RatelimitMaxKeys != 100000 ||
		c.LogLevel != slog.LevelInfo || c.LogFormat != "json" || c.ShutdownTimeout != 15*time.Second ||
		c.MetricsListen != "" || c.Realm != "" || c.UsesSecret() {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0] != want[0] || c.TrustedProxies[1] != want[1] {
		t.Fatalf("trusted proxies = %v", c.TrustedProxies)
	}
}

func TestEnvAndFlagPrecedence(t *testing.T) {
	e := base()
	e["LISTEN"] = "0.0.0.0:1111"
	e["FAIL_LIMIT"] = "9"
	e["REALM"] = "from-env"

	c, err := load(t, e, "-listen", "127.0.0.1:2222", "-fail-limit=3")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:2222" || c.FailLimit != 3 {
		t.Fatalf("flags should win: %q %d", c.Listen, c.FailLimit)
	}
	if c.Realm != "from-env" {
		t.Fatalf("env should apply when no flag: %q", c.Realm)
	}
	// A flag explicitly set to empty overrides a non-empty env value.
	c, err = load(t, e, "-realm", "")
	if err != nil || c.Realm != "" {
		t.Fatalf("empty flag should win: %q %v", c.Realm, err)
	}
}

func TestDurations(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		bad  bool
	}{
		{"600", 600 * time.Second, false},
		{"0", 0, false},
		{"10m", 10 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{" 45 ", 45 * time.Second, false},
		{"1.5s", 1500 * time.Millisecond, false},
		{"-5", 0, true},
		{"-5s", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"10x", 0, true},
	}
	for _, tc := range tests {
		got, err := ParseDuration(tc.in)
		if (err != nil) != tc.bad || got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, %v", tc.in, got, err)
		}
	}
}

func TestPrototypeEnvCompatibility(t *testing.T) {
	e := base()
	e["CACHE_TTL"] = "600"
	e["FAIL_WINDOW"] = "300"
	e["FAIL_LIMIT"] = "5"
	e["BAN_TIME"] = "900"
	e["ENTRA_TIMEOUT"] = "10"
	e["LISTEN"] = "127.0.0.1:5002"
	c, err := load(t, e)
	if err != nil {
		t.Fatal(err)
	}
	if c.CacheTTL != 10*time.Minute || c.FailWindow != 5*time.Minute || c.BanTime != 15*time.Minute || c.EntraTimeout != 10*time.Second {
		t.Fatalf("seconds not honoured: %+v", c)
	}
}

func TestRateLimitRulesBoundaryAndDisabled(t *testing.T) {
	e := base()
	e["RATELIMIT_MAX_KEYS"] = "128" // exactly 8 x 16
	e["BAN_TIME"] = "9"             // just above the 8s Entra timeout
	if _, err := load(t, e); err != nil {
		t.Fatal(err)
	}
	e["FAIL_LIMIT"] = "0" // rules only apply with the limiter on
	e["RATELIMIT_MAX_KEYS"] = "1"
	e["BAN_TIME"] = "1"
	if _, err := load(t, e); err != nil {
		t.Fatal(err)
	}
}

func TestZeroWindowAllowedWhenRateLimitDisabled(t *testing.T) {
	e := base()
	e["FAIL_LIMIT"] = "0"
	e["FAIL_WINDOW"] = "0"
	e["BAN_TIME"] = "0"
	if _, err := load(t, e); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownDrain(t *testing.T) {
	c, err := load(t, base())
	if err != nil || c.ShutdownDrain != 0 {
		t.Fatalf("default drain = %v, %v", c.ShutdownDrain, err)
	}
	e := base()
	e["SHUTDOWN_DRAIN"] = "5"
	c, _ = load(t, e)
	if c.ShutdownDrain != 5*time.Second {
		t.Fatalf("drain = %v", c.ShutdownDrain)
	}
	c, _ = load(t, e, "-shutdown-drain", "2s")
	if c.ShutdownDrain != 2*time.Second {
		t.Fatalf("flag drain = %v", c.ShutdownDrain)
	}
}

func TestEmptyNumericEnvUsesDefault(t *testing.T) {
	e := base()
	e["CACHE_TTL"] = ""
	e["FAIL_LIMIT"] = ""
	e["LOG_LEVEL"] = ""
	e["LOG_FORMAT"] = ""
	c, err := load(t, e)
	if err != nil || c.CacheTTL != 10*time.Minute || c.FailLimit != 5 || c.LogLevel != slog.LevelInfo || c.LogFormat != "json" {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestLists(t *testing.T) {
	e := base()
	e["ENTRA_ALLOWED_DOMAINS"] = " @Example.com, ,@corp.example ,Bare.Org"
	e["ENTRA_REQUIRED_GROUPS"] = "g1,g2"
	e["ENTRA_REQUIRED_ROLES"] = "Auth.User"
	e["TRUSTED_PROXIES"] = "10.0.0.0/8, 192.0.2.5 ,2001:db8::/32,10.1.2.3/8"
	c, err := load(t, e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AllowedDomains, "|") != "@example.com|@corp.example|@bare.org" {
		t.Fatalf("domains = %v", c.AllowedDomains)
	}
	if strings.Join(c.RequiredGroups, "|") != "g1|g2" || strings.Join(c.RequiredRoles, "|") != "Auth.User" {
		t.Fatalf("groups/roles = %v %v", c.RequiredGroups, c.RequiredRoles)
	}
	var got []string
	for _, p := range c.TrustedProxies {
		got = append(got, p.String())
	}
	if strings.Join(got, "|") != "10.0.0.0/8|192.0.2.5/32|2001:db8::/32|10.0.0.0/8" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestEmptyClientIPHeaderAndTrustedProxies(t *testing.T) {
	e := base()
	e["CLIENT_IP_HEADER"] = ""
	e["TRUSTED_PROXIES"] = ""
	c, err := load(t, e)
	if err != nil || c.ClientIPHeader != "" || len(c.TrustedProxies) != 0 {
		t.Fatalf("got %q %v %v", c.ClientIPHeader, c.TrustedProxies, err)
	}
}

func TestLogLevels(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError} {
		e := base()
		e["LOG_LEVEL"] = in
		c, err := load(t, e)
		if err != nil || c.LogLevel != want {
			t.Errorf("LOG_LEVEL=%s: %v %v", in, c, err)
		}
	}
}

func TestSecretFileMode(t *testing.T) {
	e := base()
	delete(e, "ENTRA_CLIENT_CERT")
	delete(e, "ENTRA_CLIENT_KEY")
	e["ENTRA_CLIENT_SECRET_FILE"] = "/run/secrets/s"
	c, err := load(t, e)
	if err != nil || !c.UsesSecret() {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(map[string]string)
		args []string
		want string
	}{
		{"missing tenant", func(e map[string]string) { delete(e, "ENTRA_TENANT_ID") }, nil, "ENTRA_TENANT_ID is required"},
		{"missing client", func(e map[string]string) { delete(e, "ENTRA_CLIENT_ID") }, nil, "ENTRA_CLIENT_ID is required"},
		{"missing scope", func(e map[string]string) { delete(e, "ENTRA_SCOPE") }, nil, "ENTRA_SCOPE is required"},
		{"no credential", func(e map[string]string) { delete(e, "ENTRA_CLIENT_CERT"); delete(e, "ENTRA_CLIENT_KEY") }, nil, "a credential is required"},
		{"cert without key", func(e map[string]string) { delete(e, "ENTRA_CLIENT_KEY") }, nil, "must be set together"},
		{"key without cert", func(e map[string]string) { delete(e, "ENTRA_CLIENT_CERT") }, nil, "must be set together"},
		{"cert and secret", func(e map[string]string) { e["ENTRA_CLIENT_SECRET_FILE"] = "/s" }, nil, "not both"},
		{"http authority", func(e map[string]string) { e["ENTRA_AUTHORITY"] = "http://login.example.com" }, nil, "must use https"},
		{"ftp authority", func(e map[string]string) { e["ENTRA_AUTHORITY"] = "ftp://x" }, nil, "must use https"},
		{"authority garbage", func(e map[string]string) { e["ENTRA_AUTHORITY"] = "not a url" }, nil, "not a valid URL"},
		{"zero timeout", func(e map[string]string) { e["ENTRA_TIMEOUT"] = "0" }, nil, "ENTRA_TIMEOUT must be greater"},
		{"bad duration", func(e map[string]string) { e["CACHE_TTL"] = "soon" }, nil, "CACHE_TTL: invalid duration"},
		{"negative duration", func(e map[string]string) { e["BAN_TIME"] = "-1" }, nil, "BAN_TIME"},
		{"bad integer", func(e map[string]string) { e["FAIL_LIMIT"] = "many" }, nil, "FAIL_LIMIT: invalid integer"},
		{"negative integer", func(e map[string]string) { e["FAIL_LIMIT"] = "-1" }, nil, "FAIL_LIMIT: must not be negative"},
		{"zero concurrency", func(e map[string]string) { e["ENTRA_MAX_CONCURRENCY"] = "0" }, nil, "at least 1"},
		{"bad cidr", func(e map[string]string) { e["TRUSTED_PROXIES"] = "10.0.0.0/33" }, nil, "invalid CIDR"},
		{"bad level", func(e map[string]string) { e["LOG_LEVEL"] = "loud" }, nil, "LOG_LEVEL"},
		{"bad format", func(e map[string]string) { e["LOG_FORMAT"] = "xml" }, nil, "LOG_FORMAT"},
		{"tenant common", func(e map[string]string) { e["ENTRA_TENANT_ID"] = "Common" }, nil, "must name one tenant"},
		{"tenant organizations", func(e map[string]string) { e["ENTRA_TENANT_ID"] = "organizations" }, nil, "must name one tenant"},
		{"tenant consumers", func(e map[string]string) { e["ENTRA_TENANT_ID"] = "CONSUMERS" }, nil, "must name one tenant"},
		{"zero window with limit", func(e map[string]string) { e["FAIL_WINDOW"] = "0" }, nil, "FAIL_WINDOW must be greater"},
		{"zero ban time with limit", func(e map[string]string) { e["BAN_TIME"] = "0" }, nil, "BAN_TIME must be greater"},
		{"ban time not above entra timeout", func(e map[string]string) { e["BAN_TIME"] = "8"; e["ENTRA_TIMEOUT"] = "8" }, nil, "BAN_TIME must be greater than ENTRA_TIMEOUT"},
		{"max keys too small", func(e map[string]string) { e["RATELIMIT_MAX_KEYS"] = "127" }, nil, "RATELIMIT_MAX_KEYS must be at least 8 x ENTRA_MAX_CONCURRENCY (128)"},
		{"empty listen", func(e map[string]string) { e["LISTEN"] = "" }, nil, "LISTEN must not be empty"},
		{"flag overrides env into error", nil, []string{"-fail-limit", "x"}, "FAIL_LIMIT"},
		{"unknown flag", nil, []string{"-nope"}, "flag provided but not defined"},
		{"positional arg", nil, []string{"stray"}, "unexpected argument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := base()
			if tc.mod != nil {
				tc.mod(e)
			}
			_, err := load(t, e, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestAllErrorsReportedTogether(t *testing.T) {
	_, err := load(t, map[string]string{"FAIL_LIMIT": "x", "CACHE_TTL": "y"})
	if err == nil || !strings.Contains(err.Error(), "FAIL_LIMIT") || !strings.Contains(err.Error(), "CACHE_TTL") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoopbackHTTPAuthorityAllowed(t *testing.T) {
	for _, a := range []string{"http://127.0.0.1:8080", "http://localhost:9", "https://login.microsoftonline.us/"} {
		e := base()
		e["ENTRA_AUTHORITY"] = a
		c, err := load(t, e)
		if err != nil {
			t.Errorf("%s: %v", a, err)
			continue
		}
		if strings.HasSuffix(c.Authority, "/") {
			t.Errorf("trailing slash kept: %q", c.Authority)
		}
	}
}

func TestHelp(t *testing.T) {
	var out bytes.Buffer
	_, err := Load([]string{"-h"}, env(nil), &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"ENTRA_TENANT_ID", "-tenant-id", "healthcheck", `default "127.0.0.1:5002"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage missing %q:\n%s", want, out.String())
		}
	}
}

func TestFailLimitIP(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		args     []string
		wantUser int
		wantIP   int
		wantErr  string
	}{
		{"unset follows FAIL_LIMIT default", nil, nil, 5, 5, ""},
		{"unset follows FAIL_LIMIT env", map[string]string{"FAIL_LIMIT": "9"}, nil, 9, 9, ""},
		{"empty env counts as unset", map[string]string{"FAIL_LIMIT": "7", "FAIL_LIMIT_IP": ""}, nil, 7, 7, ""},
		{"separate value", map[string]string{"FAIL_LIMIT": "5", "FAIL_LIMIT_IP": "20"}, nil, 5, 20, ""},
		{"zero disables IP limiting", map[string]string{"FAIL_LIMIT_IP": "0"}, nil, 5, 0, ""},
		{"flag wins over env", map[string]string{"FAIL_LIMIT_IP": "20"}, []string{"-fail-limit-ip", "0"}, 5, 0, ""},
		{"flag alone", nil, []string{"-fail-limit-ip=8"}, 5, 8, ""},
		{"IP-only limiting", map[string]string{"FAIL_LIMIT": "0", "FAIL_LIMIT_IP": "4"}, nil, 0, 4, ""},
		{"both zero", map[string]string{"FAIL_LIMIT": "0", "FAIL_LIMIT_IP": "0"}, nil, 0, 0, ""},
		{"FAIL_LIMIT zero, IP unset", map[string]string{"FAIL_LIMIT": "0"}, nil, 0, 0, ""},
		{"negative", map[string]string{"FAIL_LIMIT_IP": "-1"}, nil, 0, 0, "FAIL_LIMIT_IP: must not be negative"},
		{"not a number", map[string]string{"FAIL_LIMIT_IP": "x"}, nil, 0, 0, "FAIL_LIMIT_IP: invalid integer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := base()
			for k, v := range tc.env {
				e[k] = v
			}
			c, err := load(t, e, tc.args...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.FailLimit != tc.wantUser || c.FailLimitIP != tc.wantIP {
				t.Fatalf("limits = %d/%d, want %d/%d", c.FailLimit, c.FailLimitIP, tc.wantUser, tc.wantIP)
			}
		})
	}
}

func TestRateLimitRulesApplyWhenOnlyIPLimitSet(t *testing.T) {
	for name, mod := range map[string]func(map[string]string){
		"window":   func(e map[string]string) { e["FAIL_WINDOW"] = "0" },
		"ban time": func(e map[string]string) { e["BAN_TIME"] = "5" },
		"max keys": func(e map[string]string) { e["RATELIMIT_MAX_KEYS"] = "10" },
	} {
		e := base()
		e["FAIL_LIMIT"] = "0"
		e["FAIL_LIMIT_IP"] = "3"
		mod(e)
		if _, err := load(t, e); err == nil {
			t.Errorf("%s: expected a validation error with only FAIL_LIMIT_IP > 0", name)
		}
	}
}
