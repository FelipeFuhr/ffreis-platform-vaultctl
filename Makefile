SHELL := /bin/bash

GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
GITLEAKS ?= gitleaks
GOVULNCHECK ?= govulncheck
COVERAGE_MIN ?= 90

# vaultctl is invoked as a bare `vaultctl` command by quality-kit's
# vault.sh/vault-deploy.sh — this binary name is a locked contract, not a
# style choice. Do not rename BINARY_NAME to match the repo name.
BINARY_NAME ?= vaultctl
BUILD_DIR ?= bin
CMD_PKG := ./cmd/$(BINARY_NAME)
GOFLAGS ?= -trimpath
LDFLAGS ?= -w -s

LEFTHOOK_VERSION ?= 1.7.10
LEFTHOOK_DIR ?= $(CURDIR)/.bin
LEFTHOOK_BIN ?= $(LEFTHOOK_DIR)/lefthook

MUTATION_PACKAGES ?= ./internal/...
MUTATION_THRESHOLD ?= 60

# Integration/e2e tests run against a real DynamoDB (DynamoDB Local in a
# container), not a fake. They are build-tagged `integration`/`e2e` so they
# never run in the default `make test`, and they SKIP themselves when no
# endpoint is reachable — so a machine without a container runtime still
# gets a green `go test ./...`.
DDB_LOCAL_IMAGE ?= docker.io/amazon/dynamodb-local:2.5.2
DDB_LOCAL_CONTAINER ?= vaultctl-ddb-test
DDB_LOCAL_PORT ?= 8000
CONTAINER_ENGINE ?= podman


.PHONY: mutation help \
	build install \
	fmt fmt-check lint validate test test-race coverage-gate integration-coverage-gate quality-gates \
	ddb-local-up ddb-local-down test-integration test-e2e \
	hook-generated-drift secrets-scan-staged \
	lefthook-bootstrap lefthook-install lefthook-run lefthook setup \

	ci-list install-act ci-local \
	init-github

## mutation: run mutation testing with gremlins, one package at a time (slow — CI only)
#
# gremlins' `unleash [path]` takes exactly ONE plain directory path (not a
# go-list `...` pattern) -- passing MUTATION_PACKAGES straight through as a
# single arg silently reports "No results to report." with exit 0 (a vacuous
# pass: zero mutants tested, gate still green). Loop over each entry
# instead, stripping the trailing "/..." each one carries for `go test`
# compatibility, and propagate the worst exit code across the run. Mirrors
# the fix already applied in ffreis-platform-configctl's own Makefile.
mutation:
	@which gremlins >/dev/null 2>&1 || go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
	@status=0; \
	for pkg in $(MUTATION_PACKAGES); do \
		path=$${pkg%/...}; \
		echo "==> gremlins unleash $$path"; \
		gremlins unleash --threshold-efficacy $(MUTATION_THRESHOLD) "$$path" || status=1; \
	done; \
	exit $$status

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format all Go files in place
	$(GOFMT) -w .

fmt-check: ## Fail if Go files are not gofmt-formatted
	@./scripts/hooks/check_required_tools.sh $(GOFMT)
	@out="$$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './.git/*' -print0 | xargs -0 -r $(GOFMT) -l)"; \
	if [ -n "$$out" ]; then \
		echo "Unformatted Go files:"; \
		echo "$$out"; \
		echo "Run: $(GOFMT) -w <files>"; \
		exit 1; \
	fi

lint: ## Run golangci-lint
	@./scripts/hooks/check_required_tools.sh $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

validate: ## Static analysis and compilation check (go vet + build)
	go vet ./...
	go build -o /dev/null ./...

build: ## Compile the vaultctl binary into bin/
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PKG)

install: ## Install the vaultctl binary to GOPATH/bin
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(CMD_PKG)

test: ## Run unit tests
	go test ./...

test-race: ## Run tests with race detector
	go test -race ./...

coverage-gate: ## Run tests with coverage and fail if below COVERAGE_MIN
	@COVERAGE_MIN="$(COVERAGE_MIN)" ./scripts/hooks/check_coverage_gate.sh

integration-coverage-gate: ## Run //go:build integration tests with coverage and fail if below COVERAGE_MIN (no-op if no integration-tagged files exist)
	@COVERAGE_MIN="$(COVERAGE_MIN)" ./scripts/hooks/check_integration_coverage_gate.sh

## ddb-local-up: start DynamoDB Local for integration/e2e tests (idempotent)
ddb-local-up:
	@$(CONTAINER_ENGINE) rm -f $(DDB_LOCAL_CONTAINER) >/dev/null 2>&1 || true
	@$(CONTAINER_ENGINE) run -d --name $(DDB_LOCAL_CONTAINER) \
		-p $(DDB_LOCAL_PORT):8000 $(DDB_LOCAL_IMAGE) >/dev/null
	@printf 'waiting for DynamoDB Local'
	@for i in $$(seq 1 30); do \
		if curl -s -o /dev/null http://localhost:$(DDB_LOCAL_PORT) 2>/dev/null; then \
			echo " ready"; exit 0; \
		fi; \
		printf '.'; sleep 1; \
	done; \
	echo " TIMEOUT" >&2; exit 1

## ddb-local-down: stop and remove the DynamoDB Local container
ddb-local-down:
	@$(CONTAINER_ENGINE) rm -f $(DDB_LOCAL_CONTAINER) >/dev/null 2>&1 || true

test-integration: ## Run integration tests against DynamoDB Local (starts/stops it)
	@if ! command -v $(CONTAINER_ENGINE) >/dev/null 2>&1; then \
		echo "$(CONTAINER_ENGINE) not found -- integration tests SKIPPED."; \
		echo "  This is NOT a pass. Install $(CONTAINER_ENGINE), or point"; \
		echo "  DYNAMODB_ENDPOINT at a running DynamoDB and use: go test -tags=integration ./..."; \
		exit 0; \
	fi
	@$(MAKE) ddb-local-up
	@go test -tags=integration ./... -run 'TestIntegration' -v -count=1; \
		status=$$?; \
		$(MAKE) ddb-local-down; \
		exit $$status

test-e2e: ## Build the real vaultctl binary and exec it as a subprocess against DynamoDB Local (starts/stops it)
	@if ! command -v $(CONTAINER_ENGINE) >/dev/null 2>&1; then \
		echo "$(CONTAINER_ENGINE) not found -- e2e tests SKIPPED."; \
		echo "  This is NOT a pass. Install $(CONTAINER_ENGINE), or point"; \
		echo "  DYNAMODB_ENDPOINT at a running DynamoDB and use: go test -tags=e2e ./cmd/vaultctl/..."; \
		exit 0; \
	fi
	@$(MAKE) ddb-local-up
	@go test -tags=e2e ./cmd/vaultctl/... -run 'TestE2E' -v -count=1; \
		status=$$?; \
		$(MAKE) ddb-local-down; \
		exit $$status

quality-gates: ## Run strict pre-push quality gates (test + race + coverage + govulncheck)
	@./scripts/hooks/check_required_tools.sh $(GOVULNCHECK)
	$(MAKE) test
	$(MAKE) test-race
	$(MAKE) coverage-gate
	$(GOVULNCHECK) ./...

hook-generated-drift: ## Run generate target if present and fail on drift
	@set -euo pipefail; \
	if $(MAKE) -n generate >/dev/null 2>&1; then \
		$(MAKE) generate; \
		if ! git diff --quiet -- .; then \
			echo "Generated files are out of date. Run 'make generate' and commit updates."; \
			git status --short; \
			exit 1; \
		fi; \
	else \
		echo "No 'generate' target found; skipping generated drift check."; \
	fi

secrets-scan-staged: ## Scan staged diff for secrets
	@./scripts/hooks/check_required_tools.sh $(GITLEAKS)
	$(GITLEAKS) protect --staged --redact


lefthook-bootstrap: ## Download lefthook binary into ./.bin
	LEFTHOOK_VERSION="$(LEFTHOOK_VERSION)" BIN_DIR="$(LEFTHOOK_DIR)" bash ./scripts/bootstrap_lefthook.sh

lefthook-install: lefthook-bootstrap ## Install git hooks if missing
	@if [ -x "$(LEFTHOOK_BIN)" ] && [ -x ".git/hooks/pre-commit" ] && [ -x ".git/hooks/pre-push" ] && [ -x ".git/hooks/commit-msg" ]; then \
		echo "lefthook hooks already installed"; \
		exit 0; \
	fi
	LEFTHOOK="$(LEFTHOOK_BIN)" "$(LEFTHOOK_BIN)" install

lefthook-run: lefthook-bootstrap ## Run hooks (pre-commit + commit-msg + pre-push)
	LEFTHOOK="$(LEFTHOOK_BIN)" "$(LEFTHOOK_BIN)" run pre-commit
	@tmp_msg="$$(mktemp)"; \
	echo "chore(hooks): validate commit-msg hook" > "$$tmp_msg"; \
	LEFTHOOK="$(LEFTHOOK_BIN)" "$(LEFTHOOK_BIN)" run commit-msg -- "$$tmp_msg"; \
	rm -f "$$tmp_msg"
	LEFTHOOK="$(LEFTHOOK_BIN)" "$(LEFTHOOK_BIN)" run pre-push

lefthook: lefthook-bootstrap lefthook-install lefthook-run ## Install hooks and run them

setup: lefthook ## Install hooks and verify dev tools
	@./scripts/hooks/check_required_tools.sh $(GOLANGCI_LINT) $(GITLEAKS) $(GOVULNCHECK) || true

ci-list: ## List local CI workflows
	@ls -1 .github/workflows | sort

# ── Local CI (act-based fallback when GH Actions quota is hit) ───────────────
PLATFORM_STANDARDS_SHA ?= 3c787edb4e96ddea2e86b2add2c32139685e8db7  # v1.2.1
PLATFORM_STANDARDS_RAW ?= https://raw.githubusercontent.com/FelipeFuhr/ffreis-platform-standards

install-act: ## Download pinned act binary into .bin/
	@mkdir -p scripts
	@curl -fsSL "$(PLATFORM_STANDARDS_RAW)/$(PLATFORM_STANDARDS_SHA)/scripts/install_act.sh" \
		-o scripts/install_act.sh && chmod +x scripts/install_act.sh
	@bash ./scripts/install_act.sh

ci-local: ## Run workflows locally via act (GH Actions quota fallback). Args via ARGS=...
	@mkdir -p scripts
	@curl -fsSL "https://raw.githubusercontent.com/FelipeFuhr/ffreis-platform-ci-local/v1.0.0/scripts/run-ci-local.sh" \
		-o scripts/run-ci-local.sh && chmod +x scripts/run-ci-local.sh
	@CI_LOCAL_FINDINGS_REF=v1.0.0 PATH="$(CURDIR)/.bin:$(PATH)" bash ./scripts/run-ci-local.sh $(ARGS)

# ── GitHub repo setup (run once after gh repo create) ────────────────────────
QUALITY_KIT_SCRIPTS ?= /media/ffreis/second/projects/quality-kit/scripts

init-github: ## Apply standard fleet settings to the GitHub repo (SHA-pinning, squash-only, etc.)
	@repo=$$(git remote get-url origin 2>/dev/null | sed -E 's|.*github\.com[:/]||; s|\.git$$||'); \
	[ -n "$$repo" ] || { echo "No GitHub remote found" >&2; exit 1; }; \
	bash "$(QUALITY_KIT_SCRIPTS)/configure-repo-settings.sh" "$$repo"
