PLUGIN_NAME := vault-plugin-secrets-feature-management
BIN_DIR     := bin
PLUGIN_DIR  ?= $(CURDIR)/vault/plugins
VERSION     ?= v0.0.1
MOUNT       ?= feature-management

export VAULT_ADDR ?= http://127.0.0.1:8200

.PHONY: all build release-build release-check test cover fmt fmt-check vet tidy ci clean dev mock-server

all: build

## build: compile the plugin binary into ./bin
build:
	go build -o $(BIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

## release-build: cross-compile release archives + checksums into ./dist via GoReleaser (snapshot, no publish)
release-build:
	goreleaser release --snapshot --clean

## release-check: validate the GoReleaser config
release-check:
	goreleaser check

## test: run unit tests
test:
	go test ./...

## cover: run tests with coverage
cover:
	go test -cover ./...

## fmt: format sources
fmt:
	gofmt -w -l .

## fmt-check: fail if any file is not gofmt-clean (used by CI)
fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "needs gofmt:"; echo "$$files"; exit 1; fi

## vet: run go vet
vet:
	go vet ./...

## tidy: tidy go.mod/go.sum
tidy:
	go mod tidy

## ci: run the same checks as the CI workflow (fmt-check, vet, race tests)
ci: fmt-check vet
	go test -race ./...

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR) dist $(PLUGIN_DIR)

## dev: build into the plugin dir and (re)register + enable against a running dev Vault.
## Start a dev server first, e.g.:
##   vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR)
dev:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	PLUGIN_DIR=$(PLUGIN_DIR) PLUGIN_NAME=$(PLUGIN_NAME) VERSION=$(VERSION) MOUNT=$(MOUNT) \
		./scripts/dev-register.sh

## mock-server: run the local mock FM service (token + sdk-keys endpoints) for e2e
mock-server:
	go run ./scripts/mock-fm-server
