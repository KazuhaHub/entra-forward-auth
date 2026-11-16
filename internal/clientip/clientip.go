// Package clientip determines the address of the end client behind a trusted
// reverse proxy.
package clientip

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// warnInterval is the minimum time between two warnings for the same peer.
const warnInterval = time.Minute

// maxWarnPeers bounds the memory used to rate limit warnings.
const maxWarnPeers = 1024

// Resolver extracts client addresses from requests.
type Resolver struct {
	header  string
	trusted []netip.Prefix
	logger  *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	lastWarn map[netip.Addr]time.Time
}

// New returns a Resolver that honours header only when the TCP peer lies in
// one of the trusted prefixes. An empty header means the peer address is
// always used. A nil logger discards warnings; a nil clock means time.Now.
func New(header string, trusted []netip.Prefix, logger *slog.Logger, now func() time.Time) *Resolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Resolver{
		header:   http.CanonicalHeaderKey(header),
		trusted:  trusted,
		logger:   logger,
		now:      now,
		lastWarn: make(map[netip.Addr]time.Time),
	}
}

// Resolve returns the client address for r. The result is normalised (IPv4
// mapped IPv6 addresses unmapped, zones dropped). If even the peer address
// cannot be parsed the zero Addr is returned.
func (r *Resolver) Resolve(req *http.Request) netip.Addr {
	peer := parsePeer(req.RemoteAddr)
	if r.header == "" || !peer.IsValid() {
		return peer
	}
	if !r.isTrusted(peer) {
		// An untrusted peer sending the header is suspicious (spoof attempt
		// or a mis-set TRUSTED_PROXIES); a peer sending nothing is normal.
		if len(req.Header.Values(r.header)) > 0 {
			r.warn(peer, "client IP header ignored: peer is not a trusted proxy")
		}
		return peer
	}
	values := req.Header.Values(r.header)
	if len(values) == 0 {
		r.warn(peer, "client IP header missing from trusted proxy request", "header", r.header)
		return peer
	}

	var (
		addr netip.Addr
		ok   bool
	)
	if r.header == "X-Forwarded-For" {
		addr, ok = r.walkForwardedFor(values)
	} else {
		addr, ok = parseAddr(values[0])
	}
	if !ok {
		r.warn(peer, "client IP header invalid", "header", r.header)
		return peer
	}
	return addr
}

// walkForwardedFor walks the X-Forwarded-For list right to left and returns
// the first address that is not a trusted proxy. If every entry is trusted the
// leftmost one is returned. An unparsable entry aborts the walk.
func (r *Resolver) walkForwardedFor(values []string) (netip.Addr, bool) {
	parts := strings.Split(strings.Join(values, ","), ",")
	var last netip.Addr
	for i := len(parts) - 1; i >= 0; i-- {
		addr, ok := parseAddr(parts[i])
		if !ok {
			return netip.Addr{}, false
		}
		if !r.isTrusted(addr) {
			return addr, true
		}
		last = addr
	}
	return last, last.IsValid()
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// warn logs at most once per warnInterval per peer.
func (r *Resolver) warn(peer netip.Addr, msg string, args ...any) {
	now := r.now()
	r.mu.Lock()
	if last, ok := r.lastWarn[peer]; ok && now.Sub(last) < warnInterval {
		r.mu.Unlock()
		return
	}
	if len(r.lastWarn) >= maxWarnPeers {
		clear(r.lastWarn)
	}
	r.lastWarn[peer] = now
	r.mu.Unlock()
	r.logger.Warn(msg, append([]any{"peer", peer.String()}, args...)...)
}

func parsePeer(remote string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return normalise(ap.Addr())
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, ok := parseAddr(host)
	if !ok {
		return netip.Addr{}
	}
	return addr
}

func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return normalise(addr), true
}

func normalise(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}
