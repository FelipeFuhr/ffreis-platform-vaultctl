# ffreis-platform-vaultctl

<!-- ffreis-badges:start -->
[![CI](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/FelipeFuhr/ffreis-badges/main/badges/ffreis-platform-vaultctl/ci.json)](https://github.com/FelipeFuhr/ffreis-platform-vaultctl/actions) [![License](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/FelipeFuhr/ffreis-badges/main/badges/ffreis-platform-vaultctl/license.json)](https://github.com/FelipeFuhr/ffreis-platform-vaultctl/blob/main/LICENSE)
<!-- ffreis-badges:end -->

`vaultctl` — the fleet's credential-vault CLI. It manages secrets across the
identity/repo/root DynamoDB vault tables, keyed by an explicit `<tier>` and
`--env` (`dev`/`prod`, no default — there is no `--table` and no `--project`).

```text
vaultctl get <tier> <key> --env <env> [--reveal]
vaultctl put <tier> <key> --env <env>            # reads plaintext from stdin
vaultctl exec <tier> <key> --as <VAR> --env <env> -- <command> [args...]
vaultctl export-env <tier> <key> --as <VAR> --out <path> --env <env>
vaultctl list <tier> --env <env>
vaultctl delete <tier> <key> --env <env>
vaultctl backup export|import ...
vaultctl whoami
```

Depends on `ffreis-platform-configctl`'s public `pkg/{crypto,store,guard,
profile,backup,logger}` packages (a cross-repo Go module wired for private
access — see [`AGENTS.md`](AGENTS.md) for the `GOPRIVATE`/CI-credential
wiring and the current actual visibility of that dependency).
`internal/vaulttier/` (tier/table-name resolution) is vault-specific and
stays local, not promoted to any `pkg/`.

**Consumers:** `quality-kit`'s `/vault` and `/vault-deploy` skills invoke this
binary directly as a bare `vaultctl` command — see that repo for the actual
call sites.

## Development

This repo follows the fleet standards — git hooks (lefthook) and CI are consumed
from `ffreis-platform-standards` / `ffreis-workflows-*` by pinned reference. Where
a `Makefile` is present, `make setup` installs the hooks and `make ci` runs the
local gate (format, lint, test). See [`AGENTS.md`](AGENTS.md) for this repo's
conventions and the full set of targets.

## Badges

CI / version / license badges above are served from the public
[`ffreis-badges`](https://github.com/FelipeFuhr/ffreis-badges) mirror, so they
render even while this repo is private. They populate once this repo is in the
mirror's manifest (the poller refreshes on a schedule).

## License

See [`LICENSE`](LICENSE).
