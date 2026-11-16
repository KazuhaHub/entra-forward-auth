// Package metrics defines the Prometheus collectors exposed by the service.
// It uses its own registry rather than the global default one.
package metrics

import (
	"net/http"
	"runtime"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "entra_forward_auth"

// Metrics bundles all collectors. Label values passed to them must come from
// small fixed sets; never from request data.
type Metrics struct {
	registry *prometheus.Registry

	requests      *prometheus.CounterVec
	cacheLookups  *prometheus.CounterVec
	entraDuration *prometheus.HistogramVec
	entraRejects  *prometheus.CounterVec
	entraErrors   *prometheus.CounterVec
	bans          *prometheus.CounterVec
}

// New creates the collectors and registers them, together with the standard Go
// and process collectors and the build_info gauge, in a fresh registry.
func New(version, revision string) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "requests_total",
			Help: "Authentication decisions by result and reason.",
		}, []string{"result", "reason"}),
		cacheLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cache_lookups_total",
			Help: "Credential cache lookups by result.",
		}, []string{"result"}),
		entraDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "entra_request_duration_seconds",
			Help:    "Duration of calls to the Entra token endpoint by outcome.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16},
		}, []string{"outcome"}),
		entraRejects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "entra_rejects_total",
			Help: "Credentials rejected by Entra, by AADSTS code.",
		}, []string{"code"}),
		entraErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "entra_errors_total",
			Help: "Entra errors caused by this service's own configuration, by AADSTS code.",
		}, []string{"code"}),
		bans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "bans_total",
			Help: "Bans started, by kind of key.",
		}, []string{"kind"}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Build information; the value is always 1.",
	}, []string{"version", "revision", "goversion"})
	buildInfo.WithLabelValues(version, revision, runtime.Version()).Set(1)

	m.registry.MustRegister(
		m.requests, m.cacheLookups, m.entraDuration, m.entraRejects, m.entraErrors, m.bans, buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler returns the HTTP handler serving the registry in the Prometheus
// text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the underlying registry (used by tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// WatchCache exposes the number of cache entries, evaluated at scrape time.
func (m *Metrics) WatchCache(entries func() int) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Name: "cache_entries",
		Help: "Entries currently held in the credential cache.",
	}, func() float64 { return float64(entries()) }))
}

// WatchBanned exposes the number of banned keys per kind ("ip", "user"),
// evaluated at scrape time. count receives the key prefix ("ip:" or "user:").
func (m *Metrics) WatchBanned(count func(prefix string) int) {
	for _, kind := range []string{"ip", "user"} {
		m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: namespace, Name: "banned_keys",
			Help:        "Keys currently banned, by kind.",
			ConstLabels: prometheus.Labels{"kind": kind},
		}, func() float64 { return float64(count(kind + ":")) }))
	}
}

// Request records an authentication decision. result is "allowed", "denied"
// or "unavailable".
func (m *Metrics) Request(result, reason string) {
	m.requests.WithLabelValues(result, reason).Inc()
}

// CacheLookup records a cache lookup.
func (m *Metrics) CacheLookup(hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	m.cacheLookups.WithLabelValues(result).Inc()
}

// EntraCall records the duration of an Entra call. outcome is "accepted",
// "rejected" or "unavailable".
func (m *Metrics) EntraCall(outcome string, seconds float64) {
	m.entraDuration.WithLabelValues(outcome).Observe(seconds)
}

// EntraReject counts a rejection; code must be "AADSTS<digits>" or "other".
func (m *Metrics) EntraReject(code string) {
	m.entraRejects.WithLabelValues(code).Inc()
}

// EntraError counts a service-configuration error reported by Entra; code
// must be "AADSTS<digits>" or "other".
func (m *Metrics) EntraError(code string) {
	m.entraErrors.WithLabelValues(code).Inc()
}

// Ban counts a newly started ban for a rate limiter key such as "ip:1.2.3.4"
// or "user:alice"; only the kind prefix becomes a label value.
func (m *Metrics) Ban(key string) {
	kind, _, _ := strings.Cut(key, ":")
	if kind != "ip" && kind != "user" {
		kind = "other"
	}
	m.bans.WithLabelValues(kind).Inc()
}
