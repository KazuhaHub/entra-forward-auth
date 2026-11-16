# Design

`entra-forward-auth` lets a reverse proxy protect HTTP endpoints with a Microsoft Entra ID
username and password sent as HTTP Basic credentials. The proxy asks the service on every request
(nginx `auth_request`, Traefik `forwardAuth`, Caddy `forward_auth`); the service answers with a
status code only.

## Request flow

```
client ──Basic user:pass──▶ reverse proxy ──GET /auth (same headers)──▶ entra-forward-auth
                                   ▲                                         │
                                   └──── 204 / 401 / 503 ◀───────────────────┤
                                                                             │ cache miss only
                                                         POST /oauth2/v2.0/token (grant_type=password,
                                                         client_assertion = RS256 JWT signed with
                                                         the app's certificate key)
                                                                             ▼
                                                                    Microsoft Entra ID
```

Order of checks for `/auth` (any HTTP method; the request body is never read):

1. Resolve the client IP (see *Client IP*).
2. Parse `Authorization: Basic`. Missing / malformed / empty user or password → **401**, reason
   `no_credentials` or `malformed`. Not counted as a failure (no password was tried).
3. Normalise the username: trim spaces, lower-case.
4. Username domain allow-list (if configured): user must end with one of the suffixes → otherwise
   **401**, reason `domain`, counted as a failure against the IP key only (no `user:` key is created
   for names outside the allowed domains). A banned IP is refused here with reason `banned`.
5. If either `ip:<ip>` or `user:<user>` is banned → **401**, reason `banned`. Entra is not called. This
   check precedes the cache, so a banned user is refused even with a cached valid password (a cache
   oracle would otherwise let a locked-out account's password be probed).
6. Cache lookup by `SHA-256(salt ‖ user ‖ 0x00 ‖ password)` (salt: 32 random bytes per process).
   Hit → **204**, reason `cache`.
7. Miss → Entra ROPC call. Concurrent requests with the same cache key share one call
   (singleflight). Before the call, an attempt is **reserved** atomically on both rate-limit keys:
   the reservation is refused when a key is banned or when failures + pending attempts already
   reach `FAIL_LIMIT` → **401**, reason `throttled`. The number of concurrent Entra calls is
   bounded (semaphore) and so is the number of in-flight checks; when full → **503**, reason
   `overloaded`. The call runs detached from the client's request context: if the client goes
   away, the outcome is still recorded (failure counted, success cached).
   - Accepted (HTTP 200 with a JSON body containing `access_token`) and authorised (group / role
     check, if configured) → store in cache → **204**, reason `entra`.
   - Accepted but not authorised → **401**, reason `forbidden`, counted as a failure, not cached.
   - Service misconfiguration, an explicit list: `error` is `invalid_client`, `unauthorized_client`,
     `invalid_scope`, `unsupported_grant_type` or `invalid_resource`, or any AADSTS code among 90002,
     700016, 7000215, 7000222, 700027, 500011, 65001, 900144 (whatever the `error` string) →
     **503**, reason `unavailable`, logged at ERROR and counted in `entra_errors_total`. Not counted
     as a failure, so a broken credential cannot ban every user.
   - Rejected (any other HTTP 400/401/403 from Entra, including unknown errors: wrong password,
     locked, MFA or Conditional Access required, user not assigned, ...) → **401**, reason
     `rejected`, counted as a failure. The AADSTS code is logged and counted in metrics.
   - Unavailable (network error, timeout, HTTP 429/5xx, malformed 200 body, cannot sign assertion)
     → **503**, reason `unavailable`. Not counted as a failure, not cached.

On **204** the response carries `X-Auth-User: <normalised user>` so proxies can forward the identity
upstream. On **401** a `WWW-Authenticate: Basic realm="<realm>", charset="UTF-8"` header is added only
when a realm is configured (default: none, matching the prototype where nginx adds its own).

Differences from the Python prototype, on purpose: Entra 429/5xx are treated as *unavailable* (503)
instead of *rejected*; a 200 without a token is *unavailable*; parallel identical requests are
collapsed into one Entra call.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/entra-forward-auth` | flags + env → `config.Config`, logger, wiring, signals, graceful shutdown, `healthcheck` and `version` subcommands |
| `internal/config` | configuration struct, env/flag loading, validation, duration parsing (`600` or `10m`) |
| `internal/basicauth` | strict, allocation-light parser for `Authorization: Basic` (fuzzed) |
| `internal/clientip` | client IP resolution with trusted-proxy CIDRs |
| `internal/credential` | load PEM certificate + RSA key (PKCS#1 / PKCS#8), thumbprints, client assertion JWT; hot reload on SIGHUP |
| `internal/entra` | ROPC client: request building, response classification, AADSTS code extraction, token claim inspection |
| `internal/cache` | bounded TTL + LRU set of 32-byte keys |
| `internal/ratelimit` | sliding-window failure counter and ban list, bounded memory |
| `internal/server` | HTTP handler for `/auth`, `/healthz`, `/readyz`, `/metrics`; decision pipeline above |
| `internal/metrics` | Prometheus collectors (own registry, not the global default) |
| `internal/version` | build info injected with `-ldflags -X` |

Dependencies: standard library plus `github.com/prometheus/client_golang`. No JWT, cache or
rate-limit libraries.

## Client assertion

Header `{"alg":"RS256","typ":"JWT","x5t":b64url(SHA-1(DER)),"x5t#S256":b64url(SHA-256(DER))}`,
claims `aud` = token endpoint URL, `iss` = `sub` = client id, `jti` = random UUIDv4, `iat` = now,
`nbf` = now − 30 s, `exp` = now + 5 min. Signed with RSASSA-PKCS1-v1_5 SHA-256. A fresh assertion is
built for every Entra call (cheap; avoids replay-window bookkeeping). The certificate PEM may contain a
chain; the first certificate is the credential. Key and certificate must match (checked at load).

## Client IP

`CLIENT_IP_HEADER` (default `X-Real-IP`) is honoured only when the TCP peer is inside
`TRUSTED_PROXIES` (default `127.0.0.0/8,::1/128`). For `X-Forwarded-For` the list is walked right to
left and the first address not in `TRUSTED_PROXIES` is used. Any other header (`CF-Connecting-IP`,
`X-Real-IP`, …) is a single address. If the peer is not trusted or the header is missing/invalid, the
peer address is used and a warning is logged at most once per minute per peer. Addresses are
normalised (`netip.Addr.Unmap()`, zone dropped).

## Rate limiting

Keys `ip:<addr>` (IPv4 address, or the IPv6 /64 prefix) and `user:<name>`. Usernames rejected by
the domain allow-list count against the IP key only, so junk names cannot churn the table. Each failure appends a timestamp; timestamps older than
`FAIL_WINDOW` are dropped; when the count reaches `FAIL_LIMIT` the key is banned for `BAN_TIME` and its
history cleared (same semantics as the prototype). `FAIL_LIMIT=0` disables rate limiting. Memory is
bounded by `RATELIMIT_MAX_KEYS`: a janitor goroutine prunes expired state every minute, and when the
bound is hit the oldest-touched failure histories are evicted. Bans are never evicted early; if the
table is full of active bans, new reservations are refused (fail closed, 503 `overloaded`).

Bans are checked before the cache, on purpose: otherwise a banned user's cached password would
remain an oracle for distributed guessing. The cost is that anyone who knows a username can lock
that user out for `BAN_TIME`.
A successful login does not reset failure history (an attacker who knows one password must not get
free guesses for other accounts from the same IP).

## Cache

Bounded TTL set (`CACHE_TTL`, default 10 min; `CACHE_MAX_ENTRIES`, default 10000; LRU eviction).
Stores only the hash and expiry. `CACHE_TTL=0` disables caching. Password changes and account
disablement take effect at most `CACHE_TTL` later — documented.

## Security properties

- Passwords, the `Authorization` header, client assertions and Entra tokens are never logged,
  never stored, never put in metrics labels. The token response is read (bounded to 1 MiB), inspected
  and dropped.
- No access log by default (requests carry credentials). Log lines contain user, client IP, outcome,
  reason, AADSTS code, latency.
- Token claims used for group/role checks are read from the access token returned directly by Entra
  over TLS; the signature is not verified (the service is the token's direct recipient, not a relying
  party receiving it from a client). If the token contains a groups overage (`_claim_names.groups`),
  the group check fails closed with reason `groups_overage`.
- Metric label values are bounded: the `code` label is `AADSTS<digits>` or `other`.
- Errors sent to clients carry no detail (no user enumeration).

## Configuration

Every setting is an environment variable with an equivalent flag; flags win over env. Durations
accept bare seconds (`600`, as in the prototype) or Go durations (`10m`).

| Env | Flag | Default | Meaning |
|---|---|---|---|
| `ENTRA_TENANT_ID` | `-tenant-id` | — (required) | Directory (tenant) ID or verified domain |
| `ENTRA_CLIENT_ID` | `-client-id` | — (required) | Application (client) ID |
| `ENTRA_SCOPE` | `-scope` | — (required) | Scope to request, e.g. `api://<app-id>/Access` |
| `ENTRA_CLIENT_CERT` | `-client-cert` | — | PEM certificate file (credential) |
| `ENTRA_CLIENT_KEY` | `-client-key` | — | PEM RSA private key file |
| `ENTRA_CLIENT_SECRET_FILE` | `-client-secret-file` | — | Alternative to cert/key: file holding a client secret |
| `ENTRA_AUTHORITY` | `-authority` | `https://login.microsoftonline.com` | Authority host (sovereign clouds, tests) |
| `ENTRA_TIMEOUT` | `-entra-timeout` | `8s` | Per-request timeout to Entra |
| `ENTRA_MAX_CONCURRENCY` | `-entra-max-concurrency` | `16` | Concurrent Entra calls |
| `ENTRA_ALLOWED_DOMAINS` | `-allowed-domains` | — | Comma-separated username suffixes, e.g. `@example.com` |
| `ENTRA_REQUIRED_GROUPS` | `-required-groups` | — | Comma-separated group object IDs; any one must be in `groups` claim |
| `ENTRA_REQUIRED_ROLES` | `-required-roles` | — | Comma-separated app role values; any one must be in `roles` claim |
| `LISTEN` | `-listen` | `127.0.0.1:5002` | Listen address |
| `METRICS_LISTEN` | `-metrics-listen` | — | Separate listener for `/metrics` (default: main listener) |
| `CLIENT_IP_HEADER` | `-client-ip-header` | `X-Real-IP` | Header with the client IP; empty = peer address |
| `TRUSTED_PROXIES` | `-trusted-proxies` | `127.0.0.0/8,::1/128` | CIDRs allowed to set the client IP header |
| `REALM` | `-realm` | — | Adds `WWW-Authenticate` on 401 when set |
| `CACHE_TTL` | `-cache-ttl` | `10m` | Success cache lifetime; 0 disables |
| `CACHE_MAX_ENTRIES` | `-cache-max-entries` | `10000` | Cache bound |
| `FAIL_WINDOW` | `-fail-window` | `10m` | Failure counting window |
| `FAIL_LIMIT` | `-fail-limit` | `5` | Failures per IP / per user before a ban; 0 disables |
| `BAN_TIME` | `-ban-time` | `15m` | Ban duration |
| `RATELIMIT_MAX_KEYS` | `-ratelimit-max-keys` | `100000` | Bound on tracked IPs + users |
| `LOG_LEVEL` | `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `-log-format` | `json` | `json` or `text` |
| `SHUTDOWN_TIMEOUT` | `-shutdown-timeout` | `15s` | Graceful shutdown limit |
| `SHUTDOWN_DRAIN` | `-shutdown-drain` | `0s` | Time `/readyz` reports 503 before the listener closes |

`ENTRA_ALLOWED_DOMAINS` entries are lower-cased and get a leading `@` when missing. When both
`ENTRA_REQUIRED_GROUPS` and `ENTRA_REQUIRED_ROLES` are set, the user needs one listed group **and**
one listed role.

Validation: required values present; exactly one credential (cert + key, or secret file); files
readable and parseable at start; durations ≥ 0 (`ENTRA_TIMEOUT` > 0; `FAIL_WINDOW` and `BAN_TIME`
> 0 when `FAIL_LIMIT` > 0, and `BAN_TIME` > `ENTRA_TIMEOUT`; `RATELIMIT_MAX_KEYS` ≥ 8 ×
`ENTRA_MAX_CONCURRENCY` when `FAIL_LIMIT` > 0); limits ≥ 0; tenant is not `common`/`organizations`/`consumers`; CIDRs valid; authority is `https://`
(plain `http://` allowed only for `127.0.0.1`/`localhost`, for tests). The tenant ID and client ID
are logged at start; secrets never.

## HTTP server

`ReadHeaderTimeout` 5 s, `ReadTimeout` 10 s, `WriteTimeout` = `ENTRA_TIMEOUT` + 5 s, `IdleTimeout`
60 s, `MaxHeaderBytes` 16 KiB. On SIGINT/SIGTERM: `/readyz` turns 503, the server drains for up to
`SHUTDOWN_TIMEOUT` (after `SHUTDOWN_DRAIN`). SIGHUP reloads the certificate and key (failed reload keeps the old credential
and logs an error).

Endpoints: `/auth` (decision), `/healthz` (200 while the process runs), `/readyz` (200 when a
credential is loaded and not shutting down), `/metrics` (Prometheus). Unknown paths → 404.

The binary has subcommands `entra-forward-auth version` and `entra-forward-auth healthcheck [-url]`
(GET `/healthz`, exit 0/1) for container health checks (the distroless image has no shell or curl).

## Metrics

| Name | Type | Labels |
|---|---|---|
| `entra_forward_auth_requests_total` | counter | `result` (`allowed`,`denied`,`unavailable`), `reason` |
| `entra_forward_auth_cache_lookups_total` | counter | `result` (`hit`,`miss`) |
| `entra_forward_auth_cache_entries` | gauge | — |
| `entra_forward_auth_entra_request_duration_seconds` | histogram | `outcome` (`accepted`,`rejected`,`unavailable`) |
| `entra_forward_auth_entra_rejects_total` | counter | `code` |
| `entra_forward_auth_entra_errors_total` | counter | `code` (misconfiguration class) |
| `entra_forward_auth_bans_total` | counter | `kind` (`ip`,`user`) |
| `entra_forward_auth_banned_keys` | gauge | `kind` |
| `entra_forward_auth_build_info` | gauge | `version`, `revision`, `goversion` |

Plus the standard Go and process collectors.
