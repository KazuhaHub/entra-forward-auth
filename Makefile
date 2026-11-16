# Build tooling for entra-forward-auth.
#
# A parent go.work file may exist on a developer machine; ignore it so the
# module is always built on its own.
export GOWORK := off

MODULE   := github.com/KazuhaHub/entra-forward-auth
BINARY   := entra-forward-auth
PKG      := ./cmd/entra-forward-auth
BIN_DIR  := bin
IMAGE    ?= ghcr.io/kazuhahub/entra-forward-auth
FUZZTIME ?= 20s

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed "s/^v//" | grep . || echo dev)
REVISION ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Revision=$(REVISION)

.PHONY: all build test fuzz lint vuln image clean help

all: lint test build

help: ## List targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build the binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

test: ## Run tests with the race detector and write coverage.out
	go test -race -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

fuzz: ## Short fuzz run of the Basic auth parser
	go test ./internal/basicauth -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)

lint: ## Run golangci-lint (config: .golangci.yml)
	golangci-lint run ./...

vuln: ## Scan dependencies and the standard library with govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

image: ## Build the container image for the local platform with buildx
	docker buildx build \
		--load \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--tag $(IMAGE):$(VERSION) \
		.

clean: ## Remove build output
	rm -rf $(BIN_DIR) coverage.out coverage.html
