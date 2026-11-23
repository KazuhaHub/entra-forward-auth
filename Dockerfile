# syntax=docker/dockerfile:1

# Build stage runs on the host platform and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

WORKDIR /src

ENV GOWORK=off \
    CGO_ENABLED=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/KazuhaHub/entra-forward-auth/internal/version.Version=${VERSION} \
        -X github.com/KazuhaHub/entra-forward-auth/internal/version.Revision=${REVISION}" \
      -o /out/entra-forward-auth ./cmd/entra-forward-auth

# Final image: static binary on distroless, no shell, runs as non-root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="entra-forward-auth" \
      org.opencontainers.image.description="Forward-auth service that validates HTTP Basic credentials against Microsoft Entra ID for nginx, Traefik and Caddy" \
      org.opencontainers.image.source="https://github.com/KazuhaHub/entra-forward-auth" \
      org.opencontainers.image.url="https://github.com/KazuhaHub/entra-forward-auth" \
      org.opencontainers.image.documentation="https://github.com/KazuhaHub/entra-forward-auth#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="KazuhaHub" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=build /out/entra-forward-auth /usr/local/bin/entra-forward-auth

ENV LISTEN=0.0.0.0:5002
EXPOSE 5002
USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/entra-forward-auth", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/entra-forward-auth"]
