package clientip

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func req(remote string, hdr map[string][]string) *http.Request {
	r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
	for k, v := range hdr {
		r.Header[http.CanonicalHeaderKey(k)] = v
	}
	return r
}

func TestResolve(t *testing.T) {
	loopback := []string{"127.0.0.0/8", "::1/128"}
	tests := []struct {
		name    string
		header  string
		trusted []string
		remote  string
		hdr     map[string][]string
		want    string
	}{
		{"trusted peer X-Real-IP", "X-Real-IP", loopback, "127.0.0.1:1234", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "203.0.113.7"},
		{"untrusted peer ignores header", "X-Real-IP", loopback, "198.51.100.9:1234", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "198.51.100.9"},
		{"trusted peer header missing", "X-Real-IP", loopback, "127.0.0.1:1234", nil, "127.0.0.1"},
		{"trusted peer header invalid", "X-Real-IP", loopback, "127.0.0.1:1234", map[string][]string{"X-Real-IP": {"not-an-ip"}}, "127.0.0.1"},
		{"header with spaces", "X-Real-IP", loopback, "127.0.0.1:1", map[string][]string{"X-Real-IP": {"  203.0.113.7 "}}, "203.0.113.7"},
		{"empty header name uses peer", "", loopback, "127.0.0.1:1", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "127.0.0.1"},
		{"ipv6 client", "X-Real-IP", loopback, "[::1]:80", map[string][]string{"X-Real-IP": {"2001:db8::1"}}, "2001:db8::1"},
		{"ipv6 peer untrusted", "X-Real-IP", loopback, "[2001:db8::5]:80", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "2001:db8::5"},
		{"v4-mapped client unmapped", "CF-Connecting-IP", loopback, "127.0.0.1:1", map[string][]string{"CF-Connecting-IP": {"::ffff:203.0.113.7"}}, "203.0.113.7"},
		{"v4-mapped peer unmapped", "X-Real-IP", loopback, "[::ffff:127.0.0.1]:1", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "203.0.113.7"},
		{"zone dropped", "X-Real-IP", loopback, "127.0.0.1:1", map[string][]string{"X-Real-IP": {"fe80::1%eth0"}}, "fe80::1"},
		{"xff single", "X-Forwarded-For", loopback, "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7"},
		{"xff spoofed left entry ignored", "X-Forwarded-For", loopback, "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.7"}}, "203.0.113.7"},
		{"xff skips trusted proxies on the right", "X-Forwarded-For", append([]string{"10.0.0.0/8"}, loopback...), "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.7, 10.0.0.5, 10.0.0.6"}}, "203.0.113.7"},
		{"xff multiple header lines", "X-Forwarded-For", append([]string{"10.0.0.0/8"}, loopback...), "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7", "10.0.0.5"}}, "203.0.113.7"},
		{"xff all trusted returns leftmost", "X-Forwarded-For", append([]string{"10.0.0.0/8"}, loopback...), "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"10.0.0.1, 10.0.0.2"}}, "10.0.0.1"},
		{"xff invalid entry falls back to peer", "X-Forwarded-For", loopback, "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7, garbage"}}, "127.0.0.1"},
		{"xff empty entry falls back to peer", "X-Forwarded-For", loopback, "127.0.0.1:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7,"}}, "127.0.0.1"},
		{"xff untrusted peer", "X-Forwarded-For", loopback, "198.51.100.9:1", map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "198.51.100.9"},
		{"xff ipv6", "X-Forwarded-For", loopback, "[::1]:1", map[string][]string{"X-Forwarded-For": {"2001:db8::7, ::1"}}, "2001:db8::7"},
		{"header name case-insensitive", "x-real-ip", loopback, "127.0.0.1:1", map[string][]string{"X-Real-IP": {"203.0.113.7"}}, "203.0.113.7"},
		{"peer without port", "X-Real-IP", loopback, "198.51.100.9", nil, "198.51.100.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New(tc.header, prefixes(t, tc.trusted...), nil, nil)
			got := r.Resolve(req(tc.remote, tc.hdr))
			if got.String() != tc.want {
				t.Fatalf("Resolve = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestResolveUnparsablePeer(t *testing.T) {
	r := New("X-Real-IP", nil, nil, nil)
	if got := r.Resolve(req("@", nil)); got.IsValid() {
		t.Fatalf("expected invalid address, got %s", got)
	}
}

func TestWarningRateLimited(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	now := time.Unix(1_000_000, 0)
	r := New("X-Real-IP", prefixes(t, "127.0.0.0/8"), logger, func() time.Time { return now })

	spoof := req("198.51.100.9:1", map[string][]string{"X-Real-IP": {"1.2.3.4"}})
	for range 5 {
		r.Resolve(spoof)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("got %d warnings within a minute, want 1:\n%s", n, buf.String())
	}
	now = now.Add(61 * time.Second)
	r.Resolve(spoof)
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("got %d warnings after a minute, want 2", n)
	}
	// A different peer has its own budget.
	r.Resolve(req("198.51.100.10:1", map[string][]string{"X-Real-IP": {"1.2.3.4"}}))
	if n := strings.Count(buf.String(), "level=WARN"); n != 3 {
		t.Fatalf("got %d warnings for second peer, want 3", n)
	}
}

func TestWarnMapBounded(t *testing.T) {
	r := New("X-Real-IP", prefixes(t, "127.0.0.0/8"), nil, nil)
	for i := range maxWarnPeers + 10 {
		peer := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		r.warn(peer, "x")
	}
	if len(r.lastWarn) > maxWarnPeers {
		t.Fatalf("warn map grew to %d", len(r.lastWarn))
	}
}

func TestMissingHeaderFromUntrustedPeerIsSilent(t *testing.T) {
	var buf bytes.Buffer
	r := New("X-Real-IP", prefixes(t, "127.0.0.0/8"), slog.New(slog.NewTextHandler(&buf, nil)), nil)
	r.Resolve(req("198.51.100.9:1", nil))
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}

func FuzzResolve(f *testing.F) {
	for _, s := range []string{"", "203.0.113.7", "1.1.1.1, 10.0.0.1", "::1", "fe80::1%eth0", ",,,", "garbage, 127.0.0.1", "::ffff:1.2.3.4"} {
		f.Add(s, "127.0.0.1:1")
		f.Add(s, "[::1]:80")
		f.Add(s, "198.51.100.9:1")
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	f.Fuzz(func(t *testing.T, value, remote string) {
		for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
			got := New(header, trusted, nil, nil).Resolve(req(remote, map[string][]string{header: {value}}))
			if got.IsValid() && (got.Is4In6() || got.Zone() != "") {
				t.Fatalf("result not normalised: %v", got)
			}
		}
	})
}
