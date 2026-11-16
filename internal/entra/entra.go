// Package entra implements the Microsoft Entra ID resource owner password
// credentials (ROPC) client used to verify a username and password.
package entra

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// maxBody bounds how much of a token endpoint response is read.
const maxBody = 1 << 20 // 1 MiB

// ErrUnavailable is wrapped by every error that means "Entra could not give
// an answer" (network failure, timeout, 429/5xx, malformed response, ...).
// Such outcomes are not evidence that the credentials are wrong.
var ErrUnavailable = errors.New("entra unavailable")

// Verdict is the outcome of a completed Entra call.
type Verdict int

const (
	// Accepted means Entra issued a token and any group/role requirement is met.
	Accepted Verdict = iota + 1
	// Rejected means Entra refused the credentials.
	Rejected
	// Forbidden means Entra issued a token but the group/role requirement is not met.
	Forbidden
)

// Denial reasons reported in Result.Reason for Forbidden verdicts.
const (
	ReasonForbidden     = "forbidden"
	ReasonGroupsOverage = "groups_overage"
)

// Result describes a completed Entra call.
type Result struct {
	Verdict Verdict
	// Code is a short, sanitised diagnostic for logging: "AADSTS<n>" when
	// Entra supplied an error code, else its "error" string, else
	// "HTTP <status>". Empty for Accepted and Forbidden.
	Code string
	// Reason is the denial reason for Forbidden results.
	Reason string
}

// MetricCode returns a value safe to use as a metric label: "AADSTS<digits>"
// or "other".
func (r Result) MetricCode() string { return MetricCode(r.Code) }

// MetricCode maps a diagnostic code to a bounded metric label value:
// "AADSTS<digits>" is kept, anything else becomes "other".
func MetricCode(code string) string {
	rest, ok := strings.CutPrefix(code, "AADSTS")
	if !ok || rest == "" {
		return "other"
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return "other"
		}
	}
	return code
}

// Known service-misconfiguration errors, by OAuth error string and by AADSTS
// code (matched whatever the error string says).
var (
	misconfigErrors = map[string]bool{
		"invalid_client": true, "unauthorized_client": true, "invalid_scope": true,
		"unsupported_grant_type": true, "invalid_resource": true,
	}
	misconfigCodes = map[int]bool{
		90002: true, 700016: true, 7000215: true, 7000222: true,
		700027: true, 500011: true, 65001: true, 900144: true,
	}
)

func isMisconfiguration(oauthErr string, codes []int) bool {
	if misconfigErrors[oauthErr] {
		return true
	}
	for _, c := range codes {
		if misconfigCodes[c] {
			return true
		}
	}
	return false
}

// ServiceError means Entra refused the request for a reason that is about
// this service's own configuration or registration (wrong client credential,
// unknown tenant or app, missing consent, invalid scope, ...) rather than the
// user's credentials. It wraps ErrUnavailable: nobody can log in until an
// operator fixes it, and users must not be blamed or counted as failures.
type ServiceError struct {
	// Code is the sanitised diagnostic: "AADSTS<n>", the OAuth error string,
	// or "HTTP <status>".
	Code string
}

func (e *ServiceError) Error() string { return "entra rejected the request: " + e.Code }

// Unwrap makes errors.Is(err, ErrUnavailable) true.
func (e *ServiceError) Unwrap() error { return ErrUnavailable }

// MetricCode returns the bounded metric label for the error code.
func (e *ServiceError) MetricCode() string { return MetricCode(e.Code) }

// AssertionSigner produces client assertions (see package credential).
type AssertionSigner interface {
	Assertion(clientID, audience string) (string, error)
}

// Config configures a Client.
type Config struct {
	// Authority is the login host, e.g. https://login.microsoftonline.com.
	Authority string
	// TenantID is the directory ID or a verified domain.
	TenantID string
	// ClientID is the application (client) ID.
	ClientID string
	// Scope is the scope requested, e.g. api://<app-id>/Access.
	Scope string

	// Signer authenticates the client with a certificate. Exactly one of
	// Signer and ClientSecret must be set.
	Signer AssertionSigner
	// ClientSecret authenticates the client with a shared secret.
	ClientSecret string

	// RequiredGroups: if non-empty, one of these group object IDs must be in
	// the token's "groups" claim.
	RequiredGroups []string
	// RequiredRoles: if non-empty, one of these values must be in the
	// token's "roles" claim.
	RequiredRoles []string

	// Timeout bounds each request to Entra (default 8s).
	Timeout time.Duration
	// HTTPClient overrides the HTTP client; nil builds one that honours
	// HTTPS_PROXY and requires TLS 1.2 or newer.
	HTTPClient *http.Client
}

// Client talks to the Entra token endpoint. It is safe for concurrent use.
type Client struct {
	cfg      Config
	endpoint string
	http     *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Authority == "" || cfg.TenantID == "" || cfg.ClientID == "" || cfg.Scope == "":
		return nil, errors.New("entra: authority, tenant ID, client ID and scope are required")
	case (cfg.Signer == nil) == (cfg.ClientSecret == ""):
		return nil, errors.New("entra: exactly one of Signer and ClientSecret is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = newHTTPClient(cfg.Timeout)
	}
	return &Client{
		cfg:      cfg,
		endpoint: strings.TrimRight(cfg.Authority, "/") + "/" + url.PathEscape(cfg.TenantID) + "/oauth2/v2.0/token",
		http:     hc,
	}, nil
}

// newHTTPClient builds the default client: proxy from the environment, TLS 1.2+,
// no redirects, and a hard overall timeout.
func newHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 5 * time.Second
	tr.ResponseHeaderTimeout = timeout
	tr.MaxIdleConnsPerHost = 16
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Endpoint returns the token endpoint URL, which is also the client assertion
// audience.
func (c *Client) Endpoint() string { return c.endpoint }

// Authenticate verifies user and password against Entra.
//
// A nil error means Entra answered; Result.Verdict says how. A non-nil error
// always wraps ErrUnavailable. The password is never included in errors.
func (c *Client) Authenticate(ctx context.Context, user, password string) (Result, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {c.cfg.ClientID},
		"scope":      {c.cfg.Scope},
		"username":   {user},
		"password":   {password},
	}
	if c.cfg.Signer != nil {
		assertion, err := c.cfg.Signer.Assertion(c.cfg.ClientID, c.endpoint)
		if err != nil {
			return Result{}, fmt.Errorf("%w: sign client assertion: %w", ErrUnavailable, err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	} else {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, fmt.Errorf("%w: build request: %w", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Result{}, fmt.Errorf("%w: read response: %w", ErrUnavailable, err)
	}
	if len(body) > maxBody {
		return Result{}, fmt.Errorf("%w: response larger than %d bytes", ErrUnavailable, maxBody)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return c.classifyOK(body)
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		code, oauthErr, numeric := errorCode(resp.StatusCode, body)
		// A known list of errors that describe this service's own setup is
		// unavailable; everything else, including unknown errors, is a
		// rejection of the credentials.
		if isMisconfiguration(oauthErr, numeric) {
			return Result{}, &ServiceError{Code: code}
		}
		return Result{Verdict: Rejected, Code: code}, nil
	default:
		return Result{}, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
}

// classifyOK interprets a 200 response.
func (c *Client) classifyOK(body []byte) (Result, error) {
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return Result{}, fmt.Errorf("%w: malformed token response", ErrUnavailable)
	}
	if len(c.cfg.RequiredGroups) == 0 && len(c.cfg.RequiredRoles) == 0 {
		return Result{Verdict: Accepted}, nil
	}
	tc, err := parseTokenClaims(tr.AccessToken)
	if err != nil {
		// Cannot evaluate the policy; do not blame the user.
		return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if reason := c.authorize(tc); reason != "" {
		return Result{Verdict: Forbidden, Reason: reason}, nil
	}
	return Result{Verdict: Accepted}, nil
}

// tokenClaims is the subset of access token claims used for authorisation.
type tokenClaims struct {
	Groups     []string          `json:"groups"`
	Roles      []string          `json:"roles"`
	ClaimNames map[string]string `json:"_claim_names"`
}

// parseTokenClaims decodes the payload of a JWT without verifying its
// signature. This is acceptable only because the token was received directly
// from Entra over TLS in response to our own request.
func parseTokenClaims(token string) (tokenClaims, error) {
	var tc tokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tc, errors.New("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tc, errors.New("access token payload is not base64url")
	}
	if err := json.Unmarshal(payload, &tc); err != nil {
		return tc, errors.New("access token payload is not valid JSON")
	}
	return tc, nil
}

// authorize returns "" if the token satisfies every configured requirement,
// otherwise the denial reason. When both groups and roles are required, both
// must be satisfied.
func (c *Client) authorize(tc tokenClaims) string {
	if len(c.cfg.RequiredGroups) > 0 && !anyOf(c.cfg.RequiredGroups, tc.Groups, true) {
		if _, overage := tc.ClaimNames["groups"]; overage {
			// The groups were too many to embed; we cannot tell, so fail closed.
			return ReasonGroupsOverage
		}
		return ReasonForbidden
	}
	if len(c.cfg.RequiredRoles) > 0 && !anyOf(c.cfg.RequiredRoles, tc.Roles, false) {
		return ReasonForbidden
	}
	return ""
}

// anyOf reports whether any wanted value appears in have. Group object IDs
// are GUIDs and compared case-insensitively; app role values are exact.
func anyOf(want, have []string, fold bool) bool {
	for _, w := range want {
		for _, h := range have {
			if w == h || (fold && strings.EqualFold(w, h)) {
				return true
			}
		}
	}
	return false
}

// errorCode extracts a loggable code from an Entra error body (AADSTS<first
// error code>, else the "error" string, else "HTTP <status>") together with
// the raw OAuth "error" value and all numeric error codes.
func errorCode(status int, body []byte) (code, oauthErr string, numeric []int) {
	var e struct {
		Error      string `json:"error"`
		ErrorCodes []int  `json:"error_codes"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "HTTP " + strconv.Itoa(status), "", nil
	}
	if len(e.ErrorCodes) > 0 {
		return "AADSTS" + strconv.Itoa(e.ErrorCodes[0]), e.Error, e.ErrorCodes
	}
	if s := sanitise(e.Error); s != "" {
		return s, e.Error, nil
	}
	return "HTTP " + strconv.Itoa(status), e.Error, nil
}

// sanitise makes an untrusted string safe and short enough for log lines.
func sanitise(s string) string {
	const limit = 64
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}
