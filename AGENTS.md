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
  `github.com/FelipeFuhr/ffreis-platform-configctl v0.0.0-20260918170453-47965e6f5962`
  (the pseudo-version `go get` resolved for commit
  `47965e6f5962c48f459564449a44ab84cff49ed1`, which is that repo's `main` HEAD
  at time of pinning). This replaces an earlier pin
  (`v0.0.0-20260915013946-5160f5e72276`, for commit `5160f5e722761a97c4dc615925387fd81fd72495`
  on that repo's `feat/secret-vault-cli-guardrails` branch) that broke every
  Go-touching CI job once that branch was squash-merged and deleted — the
  original commit became unreachable, so `go mod` resolution failed with
  `invalid version: unknown revision 5160f5e72276`. **Lesson: never pin a
  pseudo-version to a commit on someone else's feature branch** — re-pin to
  that repo's `main` once the work lands there, not before, or the pin rots
  the moment the branch is cleaned up. `internal/vaulttier/` is the one
  exception: vault-specific tier/table-resolution logic with no reason to be
  shared, so it stays local and does NOT go through `pkg/` promotion here.
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
- **Every `ffreis-workflows-go` job pinned to a commit newer than its
  original scaffold pin needs its `runner` input checked, not assumed.**
  This repo has **zero self-hosted runners registered** (`gh api
  repos/FelipeFuhr/ffreis-platform-vaultctl/actions/runners` →
  `total_count: 0`) and `ffreis-org`'s self-hosted pool is not reachable
  from a personal-account repo (no runner-group sharing across that
  boundary — this will never self-resolve). At their ORIGINAL scaffold
  pins, `go-mod-tidy-check.yml`/`go-lint.yml` hardcoded `runs-on:
  ubuntu-latest`, and `go-coverage.yml`/`go-cross-build-matrix.yml`/
  `go-mutation.yml` either hardcoded it or had no `runner` input at all.
  Re-pinning any of them past the point where the fleet added a
  configurable `runner` input silently switches the default to
  `["self-hosted","local"]` — a job requesting labels this repo can never
  match queues forever and never runs, with no failure signal at all (`gh
  pr checks` just shows it pending; the GitHub API's
  `actions/jobs/{id}` `runner_name` field stays empty). `go-sonar.yml`'s
  own default flipped the same way between its v1.4.0 pin and the current
  one. Caught only by comparing `gh api .../actions/jobs/{id}` for a
  stuck-pending job against a completed sibling job in the same run, not
  by anything `actionlint` or a green-looking `gh pr checks` line would
  ever surface. Every job pinned to a self-hosted-defaulting SHA in this
  repo's workflows now passes `runner: '["ubuntu-latest"]'` explicitly —
  do the same for any future re-pin, and verify the specific pin's actual
  default via `git show <sha>:.github/workflows/<file>.yml`, never by
  assuming it matches a nearby pin or an earlier check of a different SHA.
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
  ported test files themselves. Currently ~93.0%/100% (cmd/vaultctl /
  internal/vaulttier), gate passes at 93.2%.
- **Mutation testing:** Runs monthly against `./internal/... ./cmd/vaultctl/...`
  with a `60%` efficacy threshold (both packages in `MUTATION_PACKAGES` and
  in `mutation.yml`'s `packages` input — previously `cmd/vaultctl` was
  excluded from both, meaning the cobra command wiring that decides which
  env var gets checked and whether a value gets printed was NEVER mutation
  tested; here that wiring IS the security logic, not low-value glue).
  `internal/vaulttier` kills 7/7 mutants, `cmd/vaultctl` kills 111/111 (both
  100% efficacy, 100% mutator coverage) as of the audit that added this
  line — re-run `make mutation` after any change to either package.
- **os.WriteFile does not correct a pre-existing file's permissions.** Its
  own doc says so plainly: the `mode` argument only applies when CREATING a
  new file; if the target already exists, `WriteFile` truncates and
  rewrites it "without changing permissions." `export-env` and
  `backup export` both write secret-bearing files at `0600` — a bare
  `writeFile(path, data, 0o600)` call would silently keep a pre-existing
  looser mode (e.g. `0644` left over from a different umask or another
  tool) while `export-env`'s own confirmation message kept claiming
  "mode 0600". Both commands now go through `writeSecretFile` in
  `helpers.go`, which does an explicit `chmod` after every write regardless
  of whether the file existed already. Any future command that writes
  secret material to disk must use this helper too, never a bare
  `writeFile` call.
- **Full test pyramid, matching `ffreis-platform-configctl`'s own reference
  pattern:** unit (`make test`), integration against a real DynamoDB Local
  container (`make test-integration`, ports/starts/stops it via podman or
  docker), and true black-box e2e that builds and execs the real compiled
  binary as a subprocess (`make test-e2e`). Both integration and e2e tests
  are build-tagged (`integration`/`e2e`) and self-`t.Skip` when no reachable
  endpoint is found, so a plain `go test ./...`/CI run without a container
  runtime stays green rather than silently skipping unnoticed. **This CI
  wiring was previously broken for both suites**: `integration.yml` ran
  `go test -tags=integration ./...` with no DynamoDB reachable at all (no
  service container), so every integration test silently self-skipped on
  every PR and merge to main, forever — the workflow looked green having
  executed zero real assertions. `test-e2e` had no CI workflow whatsoever;
  it only ever ran when a human happened to run it locally. Both are now
  fixed: `integration.yml` gained a `dynamodb-local` service container, and
  a new `e2e.yml` runs the e2e suite the same way. This matters because a
  raw `fmt.Println`/`os.Stdout` write bypassing `exec`/`export-env`'s
  injected `io.Writer` is NOT caught by the unit tests (which only inspect
  the writer they were handed) — only the e2e suite, which captures the
  real OS-level subprocess stdout, catches that class of leak. Verified by
  deliberately introducing exactly that leak: the unit test stayed green,
  `make test-e2e` went red.
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
