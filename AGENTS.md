# Agent Context

**This repo:** `ffreis-platform-vaultctl` — the fleet's credential-vault CLI,
`vaultctl`. Pulled out of `ffreis-platform-configctl`'s git history (commit
`699b861`, before it was removed there at `5160f5e7`) and re-homed here so
`quality-kit`'s `vault.sh`/`vault-deploy.sh` scripts (a different, already-shipped
repo) can keep invoking it as a bare `vaultctl` command — see "Command surface"
below.

## Non-obvious facts

- **Binary name is a locked contract.** The compiled binary must be literally
  `vaultctl`, never `ffreis-platform-vaultctl` — `quality-kit`'s
  `vault.sh`/`vault-deploy.sh` invoke it as a bare `vaultctl` on `$PATH`.
  `make build` produces `bin/vaultctl` from `cmd/vaultctl/` (`BINARY_NAME` in
  the Makefile). Do not rename `BINARY_NAME` to match the repo name.
- **Depends on `ffreis-platform-configctl`'s public `pkg/` packages**, not a
  vendored/forked copy. `go.mod` pins
  `github.com/FelipeFuhr/ffreis-platform-configctl v0.0.0-20260915013946-5160f5e72276`
  (the pseudo-version `go get` resolved for commit `5160f5e722761a97c4dc615925387fd81fd72495`
  on that repo's `feat/secret-vault-cli-guardrails` branch — not yet on its
  `main`). `internal/vaulttier/` is the one exception: vault-specific
  tier/table-resolution logic with no reason to be shared, so it stays local
  and does NOT go through `pkg/` promotion here.
- **`GOPRIVATE=github.com/FelipeFuhr/*` is set for `go get`/`go mod tidy`**
  (locally and in every Go-touching CI job, via a `goprivate` input +
  `GIT_AUTH_TOKEN` secret, mirroring the pattern already proven in
  `ffreis-platform-org`'s own `devops-go-ci.yml`), even though
  `ffreis-platform-configctl` is currently a **public** repo (verified via
  `gh repo view` — contrary to this dependency having been assumed private
  when this wiring was written) — public fetches don't need it at all today,
  but the wiring is future-proofed for if/when that repo goes private again,
  and costs nothing while it stays public (the token input is optional; an
  empty `GIT_AUTH_TOKEN` just skips the `git config insteadOf` step and the
  fetch proceeds unauthenticated, which is exactly what happens right now).
  The token is the fleet's canonical `FLEET_READ_TOKEN` repo secret (see
  `fleet-secrets.sh` in `quality-kit`) — **not deployed to this repo**, and
  the fleet's central PAT vault has no stored value to back-fill it from
  fleet-wide (not specific to this repo). If `ffreis-platform-configctl` ever
  goes private again, every CI job that fetches it (`mod-tidy`, `lint`,
  `test`, `integration`, `coverage`, `sonar`, `build-all`, `mutation`,
  `architecture`, `lock-sync`, `devops-security`'s `govulncheck`/`lint`) will
  start failing until a human runs
  `fleet-secrets.sh vault-put fleet-read-token-<org|ffreis>` once
  (interactive, hidden-input) and then
  `fleet-secrets.sh backfill --repo FelipeFuhr/ffreis-platform-vaultctl`.
- **`ffreis-workflows-go`'s `go-sonar.yml` and `go-cross-build-matrix.yml` had
  no `goprivate` support at all** before this repo needed it (only
  `go-mod-tidy-check.yml`/`go-lint.yml`/`go-test.yml`/`go-coverage.yml`/
  `go-integration-coverage.yml`/`go-mutation.yml`/`go-security.yml` did) —
  added upstream and released as part of wiring this repo; see that repo's
  own AGENTS.md rule 7.
- **`ffreis-workflows-go`'s `go-mutation.yml` also had a live vacuous-pass
  bug**: gremlins' `unleash [path]` doesn't understand a go-list `...`
  pattern (only one plain directory) — a single `...`-suffixed `packages`
  input (this repo's own `./internal/...` included) made gremlins print "No
  results to report." and still exit 0, so the gate was silently testing
  zero mutants. Fixed upstream (loop + strip trailing `/...` + fixed the
  score-extraction regex, which looked for a capitalized "Efficacy:" string
  gremlins never emits). This repo's own `make mutation` target carries the
  same fix locally, mirroring `ffreis-platform-configctl`'s Makefile.
- **This repo's own `.github/workflows/*.yml` were mostly missing
  `ready_for_review` in `pull_request.types`** (only `lefthook.yml` and
  `devops-pr-hygiene.yml` had it) despite several jobs gating on
  `github.event.pull_request.draft` — meaning promoting a draft PR to ready
  for review never re-triggered those workflows, so `test`/`coverage`/
  `sonar`/`build-all`'s draft-gated jobs were vacuously green having never
  run post-draft. Fixed on every Go-relevant workflow
  (`devops-go-ci.yml`, `coverage.yml`, `sonar.yml`, `build-all.yml`,
  `integration.yml`).
- **Test coverage minimum:** `COVERAGE_MIN=90` — enforced locally via
  `make coverage-gate` (pre-push) and in CI via `coverage.yml`. As pulled from
  `configctl` the ported `cmd/vaultctl` suite measured ~87.7%, below this
  repo's own (stricter than configctl's 75%) floor — closed with a handful of
  added tests (an httptest-backed STS fake for `callerIdentity`/`whoami`, an
  "unreachable AWS config" fake for `newDeleteCmd`/`newListCmd`'s RunE
  closures, one `encryptVaultValue` negative case) without touching the
  ported test files themselves. Currently ~91.6%/100% (cmd/vaultctl /
  internal/vaulttier).
- **Mutation testing:** Runs monthly against `./internal/...` with a `60%`
  efficacy threshold. Triggered by `mutation.yml`. `internal/vaulttier`
  currently kills 7/7 mutants (100% efficacy).
- **Full test pyramid, matching `ffreis-platform-configctl`'s own reference
  pattern:** unit (`make test`), integration against a real DynamoDB Local
  container (`make test-integration`, ports/starts/stops it via podman or
  docker), and true black-box e2e that builds and execs the real compiled
  binary as a subprocess (`make test-e2e`). Both integration and e2e tests
  are build-tagged (`integration`/`e2e`) and self-`t.Skip` when no reachable
  endpoint is found, so a plain `go test ./...`/CI run without a container
  runtime stays green rather than silently skipping unnoticed.
- **lefthook hooks** pull from `ffreis-platform-standards` (pinned SHA) and run
  `make quality-gates` on pre-push. Install with `make setup`. Note: the CI
  `Lefthook` workflow (`general-lefthook.yml`) runs this repo's `pre-commit`
  and `commit-msg` hooks only (`run-pre-push` defaults to `false` there and
  is not overridden) — `pre-push`'s `quality-gates` (and therefore the
  private-module fetch it implies) only actually runs locally and via the
  dedicated `devops-go-ci.yml`/`coverage.yml` jobs, not via the Lefthook
  check itself.
- **Renovate** keeps Go module dependencies and GitHub Actions SHAs updated automatically.
  It extends `ffreis-platform-standards:renovate/go`.
- **Known follow-up, not yet done:** `ffreis-workflows-general`'s
  `general-codeql.yml` (Go CodeQL compiles the code to build its database)
  has no `goprivate` support either. It only runs on `codeql.yml`'s weekly
  schedule and `devops-security.yml`'s `codeql` job (which explicitly skips
  `pull_request` events), so it never blocked this repo's own PR CI, but it
  will fail the first time it actually runs post-merge until that repo gets
  the same fix.

## Command surface

`get` / `put` / `exec` / `export-env` / `list` / `delete` / `backup` (export/
import) / `whoami`. Every command takes an explicit `<tier>` (`identity`,
`repo`, or `root`) and `--env` (`dev`/`prod`, no default) — there is no
`--table` and no `--project`; tier+env alone resolve which of the six vault
DynamoDB tables a command targets. `VAULTCTL_SECRET_KEY` must be set before
any `get`/`put`/`exec`/`export-env`/`backup` call.

**Consumers:** `quality-kit`'s `/vault` and `/vault-deploy` skills shell out to
this binary directly (`vaultctl <command> ...`) — this CLI is their entire
runtime dependency for secret access.

## Structure

```text
cmd/vaultctl/           ← CLI entry point + all subcommands (package main)
internal/vaulttier/     ← tier/table-name resolution and AAD-key derivation
scripts/hooks/          ← pre-commit and pre-push hook scripts
.github/workflows/      ← CI/CD workflows
```

## Build and run

```bash
export GOPRIVATE=github.com/FelipeFuhr/*   # needed for go get/mod tidy locally
make setup                # install lefthook git hooks
make build                # -> bin/vaultctl
make test                 # run unit tests
make test-race            # unit tests with -race
make coverage-gate        # run tests + enforce coverage minimum
make integration-coverage-gate  # //go:build integration coverage gate (no-op if untagged)
make test-integration     # real DynamoDB Local integration tests (starts/stops it)
make test-e2e             # builds the real binary, execs it against DynamoDB Local
make mutation             # gremlins mutation testing against MUTATION_PACKAGES
make quality-gates        # full pre-push gate: test + race + coverage + govulncheck
make lint                 # run golangci-lint
go run ./cmd/vaultctl --help
```

## Keeping this file current

- **If you discover a fact not reflected here:** add it before finishing your task.
- **If something here is wrong or outdated:** correct it in the same commit as the code change.
- **If you rename a file, command, or concept referenced here:** update the reference.
