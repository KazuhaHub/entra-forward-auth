# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:

<https://github.com/KazuhaHub/entra-forward-auth/security/advisories/new>

Do not open a public issue or pull request for a suspected vulnerability. Include the version
(`entra-forward-auth version`), your configuration with secrets removed, and steps to reproduce.
Never include real passwords, client secrets, private keys or tokens in a report.

You can expect an acknowledgement within 5 working days. Fixes are developed in a private advisory
and released together with the advisory. Reporters are credited unless they ask not to be.

## Supported versions

Security fixes are released for the latest minor version only. While the project is below 1.0.0,
upgrade to the newest release to receive fixes.

| Version | Supported |
|---|---|
| latest release | yes |
| older releases | no |

## Scope

In scope:

- Authentication bypass: any way to receive `204` from `/auth` without valid Entra credentials, or
  without passing the configured domain, group or role checks.
- Rate-limit or ban evasion, and client IP spoofing past the trusted-proxy rules.
- Leakage of passwords, `Authorization` headers, client assertions, tokens or key material (logs,
  metrics, error responses).
- Denial of service that a single unauthenticated client can cause with a small number of requests
  (unbounded memory or goroutine growth, for example).
- Vulnerabilities in the container image or release artifacts introduced by this repository.

Out of scope:

- Weaknesses inherent to the resource owner password credentials (ROPC) flow, such as bypassing
  multi-factor authentication. These are documented in the README, and the flow is a deliberate
  trade-off of this project.
- Misconfiguration, such as exposing the service to untrusted networks or trusting an arbitrary
  `X-Real-IP` header.
- Vulnerabilities in Microsoft Entra ID, reverse proxies or other third-party software.
- Findings that require an attacker who already controls the host, the reverse proxy or the
  service's key material.

## Verifying releases

Release binaries carry build provenance attestations and the container image is signed with
cosign (keyless) and attested. See the README for verification commands.
