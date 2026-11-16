// Package config loads and validates the service configuration from
// environment variables and command-line flags.
//
// Every setting has an environment variable and an equivalent flag. A flag
// that is given on the command line wins over the environment, which wins over
// the built-in default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is the validated service configuration.
type Config struct {
	TenantID            string
	ClientID            string
	Scope               string
	ClientCert          string
	ClientKey           string
	ClientSecretFile    string
	Authority           string
	EntraTimeout        time.Duration
	EntraMaxConcurrency int
	AllowedDomains      []string
	RequiredGroups      []string
	RequiredRoles       []string

	Listen         string
	MetricsListen  string
	ClientIPHeader string
	TrustedProxies []netip.Prefix
	Realm          string

	CacheTTL         time.Duration
	CacheMaxEntries  int
	FailWindow       time.Duration
	FailLimit        int
	BanTime          time.Duration
	RatelimitMaxKeys int

	LogLevel        slog.Level
	LogFormat       string
	ShutdownTimeout time.Duration
	ShutdownDrain   time.Duration
}

// UsesSecret reports whether the client authenticates with a secret file
// rather than a certificate.
func (c *Config) UsesSecret() bool { return c.ClientSecretFile != "" }

// setting describes one configuration knob.
type setting struct {
	env   string
	flag  string
	def   string
	usage string
}

// settings is the single source of truth for names, defaults and help text.
var settings = []setting{
	{"ENTRA_TENANT_ID", "tenant-id", "", "directory (tenant) ID or verified domain (required)"},
	{"ENTRA_CLIENT_ID", "client-id", "", "application (client) ID (required)"},
	{"ENTRA_SCOPE", "scope", "", "scope to request, e.g. api://<app-id>/Access (required)"},
	{"ENTRA_CLIENT_CERT", "client-cert", "", "PEM certificate file (credential)"},
	{"ENTRA_CLIENT_KEY", "client-key", "", "PEM RSA private key file"},
	{"ENTRA_CLIENT_SECRET_FILE", "client-secret-file", "", "alternative to cert/key: file holding a client secret"},
	{"ENTRA_AUTHORITY", "authority", "https://login.microsoftonline.com", "authority host"},
	{"ENTRA_TIMEOUT", "entra-timeout", "8s", "per-request timeout to Entra (seconds or Go duration)"},
	{"ENTRA_MAX_CONCURRENCY", "entra-max-concurrency", "16", "concurrent Entra calls"},
	{"ENTRA_ALLOWED_DOMAINS", "allowed-domains", "", "comma-separated username suffixes, e.g. @example.com"},
	{"ENTRA_REQUIRED_GROUPS", "required-groups", "", "comma-separated group object IDs; any one must be in the groups claim"},
	{"ENTRA_REQUIRED_ROLES", "required-roles", "", "comma-separated app role values; any one must be in the roles claim"},
	{"LISTEN", "listen", "127.0.0.1:5002", "listen address"},
	{"METRICS_LISTEN", "metrics-listen", "", "separate listener for /metrics (default: main listener)"},
	{"CLIENT_IP_HEADER", "client-ip-header", "X-Real-IP", "header with the client IP; empty = peer address"},
	{"TRUSTED_PROXIES", "trusted-proxies", "127.0.0.0/8,::1/128", "CIDRs allowed to set the client IP header"},
	{"REALM", "realm", "", "adds WWW-Authenticate on 401 when set"},
	{"CACHE_TTL", "cache-ttl", "10m", "success cache lifetime; 0 disables"},
	{"CACHE_MAX_ENTRIES", "cache-max-entries", "10000", "cache bound"},
	{"FAIL_WINDOW", "fail-window", "10m", "failure counting window"},
	{"FAIL_LIMIT", "fail-limit", "5", "failures per IP / per user before a ban; 0 disables"},
	{"BAN_TIME", "ban-time", "15m", "ban duration"},
	{"RATELIMIT_MAX_KEYS", "ratelimit-max-keys", "100000", "bound on tracked IPs + users"},
	{"LOG_LEVEL", "log-level", "info", "debug, info, warn or error"},
	{"LOG_FORMAT", "log-format", "json", "json or text"},
	{"SHUTDOWN_TIMEOUT", "shutdown-timeout", "15s", "graceful shutdown limit"},
	{"SHUTDOWN_DRAIN", "shutdown-drain", "0s", "after SIGTERM, keep serving with /readyz failing for this long before shutting down"},
}

// Load builds a Config from command-line arguments (without the program name)
// and an environment lookup function such as os.LookupEnv. Usage and parse
// errors are written to out. flag.ErrHelp is returned for -h/-help.
func Load(args []string, lookupEnv func(string) (string, bool), out io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("entra-forward-auth", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { usage(fs, out) }

	values := make(map[string]*string, len(settings))
	for _, s := range settings {
		def := s.def
		if v, ok := lookupEnv(s.env); ok {
			def = v
		}
		values[s.env] = fs.String(s.flag, def, s.usage)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	// Typed parsing sees "" as "use the built-in default" so that an empty
	// variable (common with container tooling) does not break numbers/durations.
	raw := func(env string) string { return *values[env] }
	p := &parser{raw: raw}

	cfg := &Config{
		TenantID:            strings.TrimSpace(raw("ENTRA_TENANT_ID")),
		ClientID:            strings.TrimSpace(raw("ENTRA_CLIENT_ID")),
		Scope:               strings.TrimSpace(raw("ENTRA_SCOPE")),
		ClientCert:          raw("ENTRA_CLIENT_CERT"),
		ClientKey:           raw("ENTRA_CLIENT_KEY"),
		ClientSecretFile:    raw("ENTRA_CLIENT_SECRET_FILE"),
		Authority:           strings.TrimRight(strings.TrimSpace(raw("ENTRA_AUTHORITY")), "/"),
		EntraTimeout:        p.duration("ENTRA_TIMEOUT"),
		EntraMaxConcurrency: p.integer("ENTRA_MAX_CONCURRENCY"),
		AllowedDomains:      domainSuffixes(raw("ENTRA_ALLOWED_DOMAINS")),
		RequiredGroups:      splitList(raw("ENTRA_REQUIRED_GROUPS"), false),
		RequiredRoles:       splitList(raw("ENTRA_REQUIRED_ROLES"), false),
		Listen:              raw("LISTEN"),
		MetricsListen:       raw("METRICS_LISTEN"),
		ClientIPHeader:      strings.TrimSpace(raw("CLIENT_IP_HEADER")),
		Realm:               raw("REALM"),
		CacheTTL:            p.duration("CACHE_TTL"),
		CacheMaxEntries:     p.integer("CACHE_MAX_ENTRIES"),
		FailWindow:          p.duration("FAIL_WINDOW"),
		FailLimit:           p.integer("FAIL_LIMIT"),
		BanTime:             p.duration("BAN_TIME"),
		RatelimitMaxKeys:    p.integer("RATELIMIT_MAX_KEYS"),
		LogFormat:           strings.ToLower(p.value("LOG_FORMAT")),
		ShutdownTimeout:     p.duration("SHUTDOWN_TIMEOUT"),
		ShutdownDrain:       p.duration("SHUTDOWN_DRAIN"),
	}
	cfg.TrustedProxies = p.prefixes("TRUSTED_PROXIES")
	cfg.LogLevel = p.level("LOG_LEVEL")

	if err := errors.Join(p.errs...); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func usage(fs *flag.FlagSet, out io.Writer) {
	fmt.Fprintln(out, "Usage: entra-forward-auth [flags]")
	fmt.Fprintln(out, "       entra-forward-auth version")
	fmt.Fprintln(out, "       entra-forward-auth healthcheck [-url http://127.0.0.1:5002/healthz]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Every flag can also be set through the environment variable shown in brackets;")
	fmt.Fprintln(out, "flags win over the environment. Durations accept seconds (600) or Go syntax (10m).")
	fmt.Fprintln(out)
	envOf := make(map[string]string, len(settings))
	for _, s := range settings {
		envOf[s.flag] = s.env
	}
	fs.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(out, "  -%s [%s]\n    \t%s", f.Name, envOf[f.Name], f.Usage)
		if def := defaultOf(f.Name); def != "" {
			fmt.Fprintf(out, " (default %q)", def)
		}
		fmt.Fprintln(out)
	})
}

func defaultOf(flagName string) string {
	for _, s := range settings {
		if s.flag == flagName {
			return s.def
		}
	}
	return ""
}

// validate checks cross-field constraints.
func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for _, r := range []struct{ name, val string }{
		{"ENTRA_TENANT_ID", c.TenantID}, {"ENTRA_CLIENT_ID", c.ClientID}, {"ENTRA_SCOPE", c.Scope},
	} {
		if r.val == "" {
			add("%s is required", r.name)
		}
	}

	switch strings.ToLower(c.TenantID) {
	case "common", "organizations", "consumers":
		add("ENTRA_TENANT_ID must name one tenant (ID or verified domain), not %q", c.TenantID)
	}

	hasCert, hasKey, hasSecret := c.ClientCert != "", c.ClientKey != "", c.ClientSecretFile != ""
	switch {
	case hasSecret && (hasCert || hasKey):
		add("set either ENTRA_CLIENT_CERT and ENTRA_CLIENT_KEY, or ENTRA_CLIENT_SECRET_FILE, not both")
	case hasCert != hasKey:
		add("ENTRA_CLIENT_CERT and ENTRA_CLIENT_KEY must be set together")
	case !hasCert && !hasSecret:
		add("a credential is required: ENTRA_CLIENT_CERT and ENTRA_CLIENT_KEY, or ENTRA_CLIENT_SECRET_FILE")
	}

	if err := checkAuthority(c.Authority); err != nil {
		errs = append(errs, err)
	}
	if c.EntraTimeout <= 0 {
		add("ENTRA_TIMEOUT must be greater than zero")
	}
	if c.EntraMaxConcurrency < 1 {
		add("ENTRA_MAX_CONCURRENCY must be at least 1")
	}
	if c.FailLimit > 0 {
		if c.FailWindow <= 0 {
			add("FAIL_WINDOW must be greater than zero when FAIL_LIMIT is set")
		}
		if c.BanTime <= 0 {
			add("BAN_TIME must be greater than zero when FAIL_LIMIT is set")
		} else if c.BanTime <= c.EntraTimeout {
			add("BAN_TIME must be greater than ENTRA_TIMEOUT when FAIL_LIMIT is set")
		}
		// Each in-flight attempt can pin two keys (IP and user), and up to
		// 4x ENTRA_MAX_CONCURRENCY attempts run at once.
		if need := 8 * c.EntraMaxConcurrency; c.RatelimitMaxKeys < need {
			add("RATELIMIT_MAX_KEYS must be at least 8 x ENTRA_MAX_CONCURRENCY (%d) when FAIL_LIMIT is set", need)
		}
	}
	if c.Listen == "" {
		add("LISTEN must not be empty")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		add("LOG_FORMAT must be json or text, got %q", c.LogFormat)
	}
	return errors.Join(errs...)
}

// checkAuthority requires https, except plain http to a loopback host (used by
// tests and local fake servers).
func checkAuthority(authority string) error {
	u, err := url.Parse(authority)
	if err != nil || u.Host == "" {
		return fmt.Errorf("ENTRA_AUTHORITY %q is not a valid URL", authority)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "127.0.0.1" || h == "localhost" {
			return nil
		}
		return errors.New("ENTRA_AUTHORITY must use https (http is only allowed for 127.0.0.1 and localhost)")
	default:
		return fmt.Errorf("ENTRA_AUTHORITY must use https, got scheme %q", u.Scheme)
	}
}

// parser accumulates parse errors so that all of them are reported at once.
type parser struct {
	raw  func(env string) string
	errs []error
}

func (p *parser) fail(env string, err error) { p.errs = append(p.errs, fmt.Errorf("%s: %w", env, err)) }

func (p *parser) defaultFor(env string) string {
	for _, s := range settings {
		if s.env == env {
			return s.def
		}
	}
	return ""
}

func (p *parser) value(env string) string {
	if v := strings.TrimSpace(p.raw(env)); v != "" {
		return v
	}
	return p.defaultFor(env)
}

func (p *parser) duration(env string) time.Duration {
	d, err := ParseDuration(p.value(env))
	if err != nil {
		p.fail(env, err)
	}
	return d
}

func (p *parser) integer(env string) int {
	n, err := strconv.Atoi(p.value(env))
	if err != nil {
		p.fail(env, fmt.Errorf("invalid integer %q", p.value(env)))
		return 0
	}
	if n < 0 {
		p.fail(env, errors.New("must not be negative"))
	}
	return n
}

func (p *parser) prefixes(env string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range splitList(p.raw(env), false) {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			// Accept a bare address as a single-host prefix.
			addr, aerr := netip.ParseAddr(s)
			if aerr != nil {
				p.fail(env, fmt.Errorf("invalid CIDR %q", s))
				continue
			}
			prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		out = append(out, prefix.Masked())
	}
	return out
}

func (p *parser) level(env string) slog.Level {
	switch strings.ToLower(p.value(env)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		p.fail(env, fmt.Errorf("must be debug, info, warn or error, got %q", p.value(env)))
		return slog.LevelInfo
	}
}

// ParseDuration parses a non-negative duration given either as bare seconds
// ("600", the format of the Python prototype) or in Go syntax ("10m").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	var d time.Duration
	if secs, err := strconv.ParseUint(s, 10, 32); err == nil {
		d = time.Duration(secs) * time.Second
	} else {
		var perr error
		d, perr = time.ParseDuration(s)
		if perr != nil {
			return 0, fmt.Errorf("invalid duration %q (use seconds like 600 or a duration like 10m)", s)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", s)
	}
	return d, nil
}

// domainSuffixes parses ENTRA_ALLOWED_DOMAINS: lower-cased suffixes, with an
// "@" prepended when missing so that "example.com" means "@example.com" and
// cannot match "user@notexample.com".
func domainSuffixes(s string) []string {
	items := splitList(s, true)
	for i, d := range items {
		if !strings.HasPrefix(d, "@") {
			items[i] = "@" + d
		}
	}
	return items
}

// splitList splits a comma-separated list, trimming blanks and dropping empty
// items; with lower set, items are lower-cased.
func splitList(s string, lower bool) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if lower {
			item = strings.ToLower(item)
		}
		out = append(out, item)
	}
	return out
}
