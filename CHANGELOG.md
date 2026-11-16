# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-16

### Added

- `/auth` endpoint for nginx `auth_request`, Traefik `forwardAuth` and Caddy `forward_auth`: validates
  HTTP Basic credentials against Microsoft Entra ID with the resource owner password credentials
  flow and answers `204`, `401` or `503`. The request body is never read.
- Confidential client authentication with a certificate (RS256 client assertion with `x5t` and
  `x5t#S256` headers) or a client secret read from a file; certificate and key reload on `SIGHUP`.
- Optional authorisation checks: username domain allow-list (a missing leading `@` is added), required
  groups (`groups` claim, case-insensitive) and required app roles (`roles` claim, exact). With both
  set the user needs one group and one role. The group check fails closed on groups overage, and an
  undecodable token with a group or role requirement answers `503`.
- Success cache keyed by a salted SHA-256 of user and password, with TTL and LRU bound; concurrent
  identical requests share one Entra call (singleflight) and concurrent Entra calls are bounded.
- Sliding-window failure rate limiting with per-IP and per-user bans and bounded memory. Attempts are
  reserved atomically before Entra is called, so parallel guessing cannot exceed `FAIL_LIMIT`, and they
  count even if the client disconnects (`401` reason `throttled`). IPv6 clients are limited per /64;
  domain allow-list rejections count against the IP only. When too many checks are in flight or the
  ban table is full the service answers `503` with reason `overloaded`.
- A fixed list of Entra errors (`invalid_client`, `unauthorized_client`, `invalid_scope`,
  `unsupported_grant_type`, `invalid_resource`, and AADSTS `90002`, `700016`, `7000215`, `7000222`,
  `700027`, `500011`, `65001`, `900144`) is treated as service misconfiguration; any other Entra
  `400`/`401`/`403` is a rejection. Misconfiguration answers `503`, logged at `ERROR`, counted in `entra_forward_auth_entra_errors_total`,
  and never blamed on the user.
- Client IP resolution from a configurable header (`X-Real-IP`, `X-Forwarded-For`, `CF-Connecting-IP`,
  ...) honoured only from trusted proxy CIDRs.
- `X-Auth-User` response header on success and optional `WWW-Authenticate` realm on `401`.
- `/healthz`, `/readyz` and Prometheus `/metrics` (optionally on a separate listener); structured
  JSON or text logs that never contain passwords or tokens; graceful shutdown with an optional drain
  period (`SHUTDOWN_DRAIN`) during which `/readyz` returns 503.
- `version` and `healthcheck` subcommands; `healthcheck` derives its URL from `LISTEN` when `-url` is
  not given.
- Configuration through environment variables or flags, with durations as seconds or Go durations.
  Validation rejects `FAIL_WINDOW` or `BAN_TIME` of 0 while `FAIL_LIMIT` is set, and the tenant values
  `common`, `organizations` and `consumers`.
- Multi-architecture distroless container image running as a non-root user, release binaries for
  Linux and macOS, `SHA256SUMS`, build provenance attestations, SBOM and keyless cosign signatures.

[Unreleased]: https://github.com/KazuhaHub/entra-forward-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/KazuhaHub/entra-forward-auth/releases/tag/v0.1.0
