# Contributing

Thanks for taking the time to contribute. Bug reports, documentation fixes and focused pull requests
are welcome.

## Development setup

Requirements: Go (the version in `go.mod`), `make`, and optionally
[golangci-lint](https://golangci-lint.run/) v2 and Docker with buildx.

```sh
git clone https://github.com/KazuhaHub/entra-forward-auth.git
cd entra-forward-auth
make test
make build
./bin/entra-forward-auth version
```

The Makefile sets `GOWORK=off`, so a `go.work` file in a parent directory does not interfere. Set it
yourself if you run `go` commands directly.

## Make targets

| Target | What it does |
|---|---|
| `make build` | Build the binary into `./bin` with version information injected |
| `make test` | Run tests with `-race` and coverage, writing `coverage.out` |
| `make fuzz` | Short fuzz run of the `Authorization: Basic` parser (`FUZZTIME=20s`) |
| `make lint` | Run golangci-lint with `.golangci.yml` |
| `make vuln` | Run govulncheck |
| `make image` | Build the container image for the local platform with buildx |
| `make clean` | Remove build output |

CI runs the same checks (`lint`, `test`, `vulncheck`, `build`, `image`); all must pass.

## Guidelines

- Keep the dependency set small: the standard library plus the Prometheus client. Discuss new
  dependencies in an issue first.
- Never log or store passwords, `Authorization` headers, client assertions or tokens, and never put
  them in metric labels.
- Add tests for behaviour changes. Parsers of untrusted input should have fuzz targets.
- Update `docs/design.md` and the README when behaviour or configuration changes, and add an entry
  under `## [Unreleased]` in `CHANGELOG.md`.
- Use placeholders (`00000000-0000-0000-0000-000000000000`, `example.com`) in docs and tests, never
  real tenant IDs, client IDs or domains.

## Commit messages

Plain, imperative, conventional-ish. A short subject line (about 72 characters) that says what
changed, optionally prefixed with a type such as `fix:`, `feat:`, `docs:`, `ci:` or `chore:`.
Use the body to explain why when it is not obvious.

```
fix: treat Entra 429 as unavailable instead of rejected
```

A Developer Certificate of Origin sign-off is not required.

## Pull requests

1. Fork and create a topic branch (`fix/...`, `feat/...`, `docs/...`).
2. Keep the change focused; open an issue first for larger changes.
3. Run `make lint test` locally.
4. Open the pull request against `main` and fill in the template.
5. A maintainer reviews it; address feedback with additional commits. Pull requests are squash
   merged.

## Security issues

Do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0.
