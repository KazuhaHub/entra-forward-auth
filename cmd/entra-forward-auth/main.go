// Command entra-forward-auth is a forward-auth service that lets a reverse
// proxy protect HTTP endpoints with a Microsoft Entra ID username and
// password sent as HTTP Basic credentials.
//
// Usage:
//
//	entra-forward-auth [flags]                 run the service
//	entra-forward-auth version                 print version information
//	entra-forward-auth healthcheck [-url URL]  probe /healthz (exit 0 or 1)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/entra-forward-auth/internal/cache"
	"github.com/KazuhaHub/entra-forward-auth/internal/clientip"
	"github.com/KazuhaHub/entra-forward-auth/internal/config"
	"github.com/KazuhaHub/entra-forward-auth/internal/credential"
	"github.com/KazuhaHub/entra-forward-auth/internal/entra"
	"github.com/KazuhaHub/entra-forward-auth/internal/metrics"
	"github.com/KazuhaHub/entra-forward-auth/internal/ratelimit"
	"github.com/KazuhaHub/entra-forward-auth/internal/server"
	"github.com/KazuhaHub/entra-forward-auth/internal/version"
)

const (
	defaultListen    = "127.0.0.1:5002"
	defaultHealthURL = "http://" + defaultListen + "/healthz"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

// run dispatches subcommands and returns the process exit code.
func run(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Fprintf(stdout, "entra-forward-auth %s %s\n", version.String(), runtime.Version())
			return 0
		case "healthcheck":
			return healthcheck(args[1:], stderr, lookupEnv)
		}
	}

	cfg, err := config.Load(args, lookupEnv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "entra-forward-auth: configuration error:\n%v\n", err)
		return 2
	}
	logger := newLogger(stderr, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)

	if err := serve(ctx, cfg, logger, reload, nil); err != nil {
		logger.Error("fatal", "error", err)
		return 1
	}
	return 0
}

func newLogger(w io.Writer, cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// healthcheck implements the "healthcheck" subcommand.
//
// Without -url, the URL is derived from -listen, else the LISTEN environment
// variable, else the default listen address, so a container that only sets
// LISTEN is probed on the right port.
func healthcheck(args []string, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("url", "", "URL of the health endpoint (default: derived from -listen / LISTEN)")
	listen := fs.String("listen", "", "service listen address to derive the URL from (default: $LISTEN)")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *target == "" {
		addr := *listen
		if addr == "" {
			addr, _ = lookupEnv("LISTEN")
		}
		*target = healthURL(addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *target, http.NoBody)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	// Probe directly: never route a local health check through a proxy.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck: unexpected status %s\n", resp.Status)
		return 1
	}
	return 0
}

// healthURL builds the /healthz URL for a service listening on listen. A
// wildcard or empty host becomes the loopback address; an unusable value
// falls back to the default.
func healthURL(listen string) string {
	if strings.TrimSpace(listen) == "" {
		return defaultHealthURL
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return defaultHealthURL
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// authSetup is the Entra client together with the hooks that depend on how
// the application authenticates.
type authSetup struct {
	client *entra.Client
	ready  func() bool
	reload func() error // nil when there is nothing to reload
}

func newAuth(cfg *config.Config, logger *slog.Logger) (*authSetup, error) {
	ecfg := entra.Config{
		Authority:      cfg.Authority,
		TenantID:       cfg.TenantID,
		ClientID:       cfg.ClientID,
		Scope:          cfg.Scope,
		RequiredGroups: cfg.RequiredGroups,
		RequiredRoles:  cfg.RequiredRoles,
		Timeout:        cfg.EntraTimeout,
	}
	setup := &authSetup{ready: func() bool { return true }}

	if cfg.UsesSecret() {
		raw, err := os.ReadFile(cfg.ClientSecretFile) //nolint:gosec // the path is operator configuration, not request input.
		if err != nil {
			return nil, fmt.Errorf("read client secret file: %w", err)
		}
		ecfg.ClientSecret = strings.TrimSpace(string(raw))
		if ecfg.ClientSecret == "" {
			return nil, errors.New("client secret file is empty")
		}
	} else {
		signer, err := credential.NewSigner(cfg.ClientCert, cfg.ClientKey, nil)
		if err != nil {
			return nil, err
		}
		ecfg.Signer = signer
		setup.ready = signer.Loaded
		setup.reload = signer.Reload
		if left := time.Until(signer.Current().NotAfter()); left < 30*24*time.Hour {
			logger.Warn("client certificate expires soon", "not_after", signer.Current().NotAfter().UTC().Format(time.RFC3339))
		}
	}

	client, err := entra.New(ecfg)
	if err != nil {
		return nil, err
	}
	setup.client = client
	return setup, nil
}

// serve runs the service until ctx is cancelled or a listener fails. Signals
// received on reload trigger a credential reload. onListen, if not nil, is
// told the bound address of each listener ("main", "metrics").
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, reload <-chan os.Signal, onListen func(name string, addr net.Addr)) error {
	auth, err := newAuth(cfg, logger)
	if err != nil {
		return err
	}

	m := metrics.New(version.Version, version.Revision)
	credCache := cache.New(cfg.CacheTTL, cfg.CacheMaxEntries, nil)
	limiter := ratelimit.New(ratelimit.Config{
		// IP keys have their own limit so that callers sharing one source
		// address (for example a RADIUS server) are not locked out together.
		KeyLimit: func(key string) int {
			if strings.HasPrefix(key, "ip:") {
				return cfg.FailLimitIP
			}
			return cfg.FailLimit
		},
		Window:  cfg.FailWindow,
		BanTime: cfg.BanTime,
		MaxKeys: cfg.RatelimitMaxKeys,
		OnBan:   m.Ban,
	})
	m.WatchCache(credCache.Len)
	m.WatchBanned(limiter.CountBanned)

	srv, err := server.New(server.Config{
		Authenticator:   auth.client,
		IPs:             clientip.New(cfg.ClientIPHeader, cfg.TrustedProxies, logger, nil),
		Cache:           credCache,
		Limiter:         limiter,
		Metrics:         m,
		Logger:          logger,
		Realm:           cfg.Realm,
		AllowedDomains:  cfg.AllowedDomains,
		MaxConcurrency:  cfg.EntraMaxConcurrency,
		EntraTimeout:    cfg.EntraTimeout,
		Ready:           auth.ready,
		SeparateMetrics: cfg.MetricsListen != "",
	})
	if err != nil {
		return err
	}

	bg, cancelBG := context.WithCancel(ctx)
	defer cancelBG()
	go credCache.Run(bg, time.Minute)
	go limiter.Run(bg, time.Minute)
	go reloadLoop(bg, reload, auth.reload, logger)

	type listener struct {
		name string
		srv  *http.Server
		ln   net.Listener
	}
	var listeners []listener
	open := func(name, addr string, h http.Handler) error {
		ln, err := new(net.ListenConfig).Listen(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", name, err)
		}
		if onListen != nil {
			onListen(name, ln.Addr())
		}
		listeners = append(listeners, listener{name, server.NewHTTPServer(addr, h, cfg.EntraTimeout), ln})
		return nil
	}
	if err := open("main", cfg.Listen, srv.Handler()); err != nil {
		return err
	}
	if cfg.MetricsListen != "" {
		if err := open("metrics", cfg.MetricsListen, srv.MetricsHandler()); err != nil {
			_ = listeners[0].ln.Close()
			return err
		}
	}

	logger.Info("starting",
		"version", version.Version, "revision", version.Revision,
		"tenant_id", cfg.TenantID, "client_id", cfg.ClientID,
		"listen", listeners[0].ln.Addr().String(), "metrics_listen", cfg.MetricsListen,
		"cache_ttl", cfg.CacheTTL.String(), "fail_limit", cfg.FailLimit, "fail_limit_ip", cfg.FailLimitIP,
	)

	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			if err := l.srv.Serve(l.ln); !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", l.name, err)
				return
			}
			errCh <- nil
		}()
	}

	var serveErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down", "drain", cfg.ShutdownDrain.String())
		// Fail /readyz first, and keep serving for the drain period so the
		// proxy notices before connections start closing.
		srv.SetShuttingDown()
		if cfg.ShutdownDrain > 0 {
			select {
			case <-time.After(cfg.ShutdownDrain):
			case serveErr = <-errCh:
			}
		}
	case serveErr = <-errCh:
	}

	srv.SetShuttingDown()
	// ctx is already cancelled here; the drain needs a fresh deadline.
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
	defer cancel()
	for _, l := range listeners {
		if err := l.srv.Shutdown(shutCtx); err != nil {
			logger.Warn("shutdown incomplete", "listener", l.name, "error", err)
			_ = l.srv.Close()
		}
	}
	return serveErr
}

// reloadLoop reloads the credential whenever a signal arrives. A failed reload
// keeps the old credential.
func reloadLoop(ctx context.Context, sigs <-chan os.Signal, reload func() error, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			if reload == nil {
				logger.Info("reload requested; nothing to reload (client secret mode)")
				continue
			}
			if err := reload(); err != nil {
				logger.Error("credential reload failed; keeping the previous credential", "error", err)
				continue
			}
			logger.Info("credential reloaded")
		}
	}
}
