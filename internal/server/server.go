// Package server implements the HTTP surface of the service: the /auth
// decision endpoint used by reverse proxies, plus health, readiness and
// metrics endpoints.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/entra-forward-auth/internal/basicauth"
	"github.com/KazuhaHub/entra-forward-auth/internal/cache"
	"github.com/KazuhaHub/entra-forward-auth/internal/entra"
	"github.com/KazuhaHub/entra-forward-auth/internal/metrics"
	"github.com/KazuhaHub/entra-forward-auth/internal/ratelimit"
)

// Authenticator verifies a username and password against the identity
// provider. Implementations return an error wrapping entra.ErrUnavailable
// when no answer could be obtained.
type Authenticator interface {
	Authenticate(ctx context.Context, user, password string) (entra.Result, error)
}

// IPResolver determines the client address of a request.
type IPResolver interface {
	Resolve(r *http.Request) netip.Addr
}

// Decision reasons, used in logs and as the "reason" metric label. The
// reasons "forbidden" and "groups_overage" come from the entra package.
//
// "banned": a key is banned. "throttled": nothing is banned yet, but failures
// plus attempts still waiting on Entra already use up the budget of the IP or
// user, so further attempts are refused (401) until those settle; this is what
// keeps parallel guesses from outrunning FAIL_LIMIT. "overloaded" (503): too
// many attempts are in flight, or the rate limiter table is full of bans; the
// service fails closed instead of queueing without bound.
const (
	reasonNoCredentials = "no_credentials"
	reasonMalformed     = "malformed"
	reasonBanned        = "banned"
	reasonThrottled     = "throttled"
	reasonOverloaded    = "overloaded"
	reasonDomain        = "domain"
	reasonCache         = "cache"
	reasonEntra         = "entra"
	reasonRejected      = "rejected"
	reasonUnavailable   = "unavailable"
)

// Config holds the dependencies and settings of a Server.
type Config struct {
	Authenticator Authenticator
	IPs           IPResolver
	Cache         *cache.Cache
	Limiter       *ratelimit.Limiter
	Metrics       *metrics.Metrics
	Logger        *slog.Logger

	// Realm, if non-empty, is advertised in WWW-Authenticate on 401.
	Realm string
	// AllowedDomains are lower-case username suffixes; empty allows all.
	AllowedDomains []string
	// MaxConcurrency bounds simultaneous Entra calls (default 16). At most
	// 4*MaxConcurrency attempts may be in flight at once.
	MaxConcurrency int
	// EntraTimeout bounds one attempt, including the wait for a free Entra
	// call slot (default 8s).
	EntraTimeout time.Duration
	// Ready reports whether a credential is loaded; nil means always ready.
	Ready func() bool
	// SeparateMetrics leaves /metrics off the main handler; serve
	// MetricsHandler on its own listener instead.
	SeparateMetrics bool
	// Now is the clock used for latency measurements; nil means time.Now.
	Now func() time.Time
}

// Server is the HTTP handler set. Create one with New.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	salt     [32]byte
	sem      chan struct{}
	flights  flightGroup
	shutting atomic.Bool
	now      func() time.Time
	realmHdr string

	lastFullLog atomic.Int64 // unix nanos of the last "table full" error log
}

// New returns a Server. The per-process cache salt is generated here.
func New(cfg Config) (*Server, error) {
	s := &Server{cfg: cfg, logger: cfg.Logger, now: cfg.Now}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if _, err := rand.Read(s.salt[:]); err != nil {
		return nil, err
	}
	n := cfg.MaxConcurrency
	if n < 1 {
		n = 16
	}
	s.sem = make(chan struct{}, n)
	s.flights.max = 4 * n
	if s.cfg.EntraTimeout <= 0 {
		s.cfg.EntraTimeout = 8 * time.Second
	}
	if cfg.Realm != "" {
		esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(cfg.Realm)
		s.realmHdr = `Basic realm="` + esc + `", charset="UTF-8"`
	}
	return s, nil
}

// SetShuttingDown makes /readyz report 503 so the proxy stops sending traffic.
func (s *Server) SetShuttingDown() { s.shutting.Store(true) }

// Handler returns the main handler: /auth, /healthz, /readyz and, unless
// Config.SeparateMetrics is set, /metrics. Unknown paths yield 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	if !s.cfg.SeparateMetrics {
		mux.Handle("/metrics", s.cfg.Metrics.Handler())
	}
	return mux
}

// MetricsHandler returns a handler serving only /metrics, for a dedicated
// listener.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.cfg.Metrics.Handler())
	return mux
}

// NewHTTPServer returns an http.Server with the timeouts and limits required
// for a service that sits behind a reverse proxy.
func NewHTTPServer(addr string, h http.Handler, entraTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      entraTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.shutting.Load() || (s.cfg.Ready != nil && !s.cfg.Ready()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

// outcome is the final decision for one /auth request.
type outcome struct {
	status int // 204, 401 or 503
	reason string
	code   string // Entra diagnostic code, for logs only
}

// handleAuth runs the decision pipeline. The request body is never read.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	ip := s.cfg.IPs.Resolve(r)
	out, user := s.decide(r, ip)
	s.respond(w, out, user)
	s.record(r.Context(), out, ip, user, s.now().Sub(start))
}

// decide implements the ordered checks of the design and returns the
// decision together with the normalised user name ("" if none was parsed).
func (s *Server) decide(r *http.Request, ip netip.Addr) (out outcome, user string) {
	user, password, err := basicauth.Parse(r.Header.Get("Authorization"))
	if err != nil {
		reason := reasonMalformed
		if errors.Is(err, basicauth.ErrNoCredentials) {
			reason = reasonNoCredentials
		}
		return outcome{status: http.StatusUnauthorized, reason: reason}, ""
	}
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" {
		return outcome{status: http.StatusUnauthorized, reason: reasonMalformed}, ""
	}

	ipKey, userKey := limiterIPKey(ip), "user:"+user
	lim := s.cfg.Limiter

	if !s.domainAllowed(user) {
		// Counted against the IP only: user keys are never created for names
		// outside the allowed domains, so they cannot be used to fill the table.
		rsv, st := lim.Reserve(ipKey)
		if st != ratelimit.Allowed {
			return s.refusal(st), user
		}
		rsv.Fail()
		return outcome{status: http.StatusUnauthorized, reason: reasonDomain}, user
	}

	// Banned callers are refused even when their password is cached, so the
	// cache cannot be used to probe passwords of a locked-out account.
	if lim.Banned(ipKey) || lim.Banned(userKey) {
		return outcome{status: http.StatusUnauthorized, reason: reasonBanned}, user
	}

	key := s.cacheKey(user, password)
	if s.cfg.Cache.Has(key) {
		s.cfg.Metrics.CacheLookup(true)
		return outcome{status: http.StatusNoContent, reason: reasonCache}, user
	}
	s.cfg.Metrics.CacheLookup(false)

	ar, err := s.flights.do(r.Context(), key, func(ctx context.Context) attemptResult {
		return s.attempt(ctx, ipKey, userKey, user, password, key)
	})
	switch {
	case errors.Is(err, errOverloaded):
		return outcome{status: http.StatusServiceUnavailable, reason: reasonOverloaded}, user
	case err != nil: // this client gave up waiting; the attempt is still recorded
		return outcome{status: http.StatusServiceUnavailable, reason: reasonUnavailable}, user
	case ar.refused != ratelimit.Allowed:
		return s.refusal(ar.refused), user
	case ar.err != nil:
		return outcome{status: http.StatusServiceUnavailable, reason: reasonUnavailable}, user
	case ar.res.Verdict == entra.Accepted:
		return outcome{status: http.StatusNoContent, reason: reasonEntra}, user
	case ar.res.Verdict == entra.Forbidden:
		return outcome{status: http.StatusUnauthorized, reason: ar.res.Reason}, user
	default:
		return outcome{status: http.StatusUnauthorized, reason: reasonRejected, code: ar.res.Code}, user
	}
}

// attempt is the body of a flight. It reserves the attempt against the rate
// limiter, asks Entra, and records the outcome (failure count, cache store)
// itself: nothing depends on any waiting client still being connected.
//
// A panic anywhere in the attempt must not leave a pending reservation behind
// (it would eat the budget of the keys until restart) or take the process
// down, so it is recovered into an unavailable result. Only the panic's type
// is logged: its value could carry request data.
func (s *Server) attempt(ctx context.Context, ipKey, userKey, user, password string, key cache.Key) (result attemptResult) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.EntraTimeout)
	defer cancel()

	var rsv *ratelimit.Reservation
	defer func() {
		if p := recover(); p != nil {
			rsv.Release() // nil-safe
			s.logger.Error("panic while handling an authentication attempt", "panic_type", fmt.Sprintf("%T", p))
			result = attemptResult{err: fmt.Errorf("%w: internal error", entra.ErrUnavailable)}
		}
	}()

	rsv, st := s.cfg.Limiter.Reserve(ipKey, userKey)
	if st != ratelimit.Allowed {
		return attemptResult{refused: st}
	}
	res, err := s.callEntra(ctx, user, password)
	switch {
	case err != nil:
		rsv.Release() // no answer is not evidence of a wrong password
	case res.Verdict == entra.Accepted:
		rsv.Release()
		// Cached before the flight ends, so a request arriving right after
		// it finishes hits the cache instead of starting another call.
		s.cfg.Cache.Add(key)
	default:
		rsv.Fail()
	}
	return attemptResult{res: res, err: err}
}

// refusal maps a limiter refusal to a response.
func (s *Server) refusal(st ratelimit.Status) outcome {
	switch st {
	case ratelimit.Banned:
		return outcome{status: http.StatusUnauthorized, reason: reasonBanned}
	case ratelimit.Throttled:
		return outcome{status: http.StatusUnauthorized, reason: reasonThrottled}
	case ratelimit.Allowed, ratelimit.Full:
		// Allowed is not a refusal and never passed here; both fail closed.
	}
	now := s.now()
	last := s.lastFullLog.Load()
	if now.UnixNano()-last >= int64(time.Minute) && s.lastFullLog.CompareAndSwap(last, now.UnixNano()) {
		s.logger.Error("rate-limit table is full (active bans or in-flight attempts); refusing new attempts (consider raising RATELIMIT_MAX_KEYS)")
	}
	return outcome{status: http.StatusServiceUnavailable, reason: reasonOverloaded}
}

// limiterIPKey is the rate limiter key for a client address. IPv6 clients
// usually control a whole /64, so the prefix is the unit; IPv4 uses the address.
func limiterIPKey(ip netip.Addr) string {
	if ip.Is6() {
		return "ip:" + netip.PrefixFrom(ip, 64).Masked().String()
	}
	return "ip:" + ip.String()
}

// callEntra performs one bounded, instrumented Entra call. ctx is detached
// from any single request; waiting for a call slot honours it.
func (s *Server) callEntra(ctx context.Context, user, password string) (entra.Result, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		s.cfg.Metrics.EntraCall("unavailable", 0)
		return entra.Result{}, fmt.Errorf("%w: waiting for a free call slot: %w", entra.ErrUnavailable, ctx.Err())
	}

	start := s.now()
	res, err := s.cfg.Authenticator.Authenticate(ctx, user, password)
	elapsed := s.now().Sub(start).Seconds()
	var svcErr *entra.ServiceError
	switch {
	case errors.As(err, &svcErr):
		// Entra refused the request itself: our registration, secret,
		// scope or tenant is wrong. Needs an operator, not a retry.
		s.cfg.Metrics.EntraCall("unavailable", elapsed)
		s.cfg.Metrics.EntraError(svcErr.MetricCode())
		s.logger.Error("entra reported a service misconfiguration", "code", svcErr.Code)
	case err != nil:
		s.cfg.Metrics.EntraCall("unavailable", elapsed)
		// The error describes transport problems only, never the password.
		s.logger.Warn("entra unavailable", "user", clip(user), "error", err)
	case res.Verdict == entra.Rejected:
		s.cfg.Metrics.EntraCall("rejected", elapsed)
		s.cfg.Metrics.EntraReject(res.MetricCode())
	default:
		s.cfg.Metrics.EntraCall("accepted", elapsed)
	}
	return res, err
}

func (s *Server) domainAllowed(user string) bool {
	if len(s.cfg.AllowedDomains) == 0 {
		return true
	}
	for _, suffix := range s.cfg.AllowedDomains {
		if strings.HasSuffix(user, suffix) {
			return true
		}
	}
	return false
}

// cacheKey is SHA-256(salt ‖ user ‖ 0x00 ‖ password). The salt is random per
// process, so keys are meaningless outside it.
func (s *Server) cacheKey(user, password string) cache.Key {
	h := sha256.New()
	h.Write(s.salt[:])
	h.Write([]byte(user))
	h.Write([]byte{0})
	h.Write([]byte(password))
	var k cache.Key
	h.Sum(k[:0])
	return k
}

func (s *Server) respond(w http.ResponseWriter, out outcome, user string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	switch out.status {
	case http.StatusNoContent:
		h.Set("X-Auth-User", user)
	case http.StatusUnauthorized:
		if s.realmHdr != "" {
			h.Set("WWW-Authenticate", s.realmHdr)
		}
	}
	w.WriteHeader(out.status)
}

// record updates metrics and writes the log line. Successful requests are
// logged at debug level only: the service has no access log by default.
func (s *Server) record(ctx context.Context, out outcome, ip netip.Addr, user string, took time.Duration) {
	result, level := "denied", slog.LevelInfo
	switch out.status {
	case http.StatusNoContent:
		result, level = "allowed", slog.LevelDebug
	case http.StatusServiceUnavailable:
		result, level = "unavailable", slog.LevelWarn
	}
	s.cfg.Metrics.Request(result, out.reason)

	if !s.logger.Enabled(ctx, level) {
		return
	}
	attrs := []any{"outcome", result, "reason", out.reason, "ip", ip.String(), "latency", took}
	if user != "" {
		attrs = append(attrs, "user", clip(user))
	}
	if out.code != "" {
		attrs = append(attrs, "code", out.code)
	}
	s.logger.Log(ctx, level, "auth", attrs...)
}

// clip bounds attacker-controlled strings in log lines, without cutting a
// UTF-8 sequence in half.
func clip(s string) string {
	const limit = 128
	if len(s) <= limit {
		return s
	}
	n := limit
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
