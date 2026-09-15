package main

const (
	flagEnv    = "env"
	flagAs     = "as"
	flagOut    = "out"
	flagTier   = "tier"
	flagReveal = "reveal"

	checksumFormatSHA256 = "sha256:%x"

	// vaultProject is the literal "project" value used in the PK for every
	// vaultctl-managed item. This vault has no sub-project dimension — tier
	// (which physical table) and env (dev/prod) already partition
	// everything, so there is no --project flag at all.
	vaultProject = "vault"

	// envPassphrase names the env var holding the passphrase used to derive
	// the AES-256-GCM key, via the same Argon2id derivation
	// platform-configctl uses. Its own env var name, not CONFIGCTL_SECRET_KEY
	// — the two tools are independent even though they share internals, so a
	// shell that happens to have CONFIGCTL_SECRET_KEY set must never
	// silently satisfy vaultctl too.
	//
	// #nosec G101 -- this is the NAME of an environment variable to read,
	// never a credential value; gosec's hardcoded-credential heuristic
	// matches on the identifier containing "secret", not on the string
	// actually being sensitive.
	envPassphrase = "VAULTCTL_SECRET_KEY"

	// envLogLevel overrides the default log level, mirroring
	// CONFIGCTL_LOG_LEVEL under vaultctl's own name.
	envLogLevel = "VAULTCTL_LOG_LEVEL"

	// envNoReveal is vaultctl's own reveal kill switch: when set to a
	// truthy value (see internal/guard.EnvTruthy), 'get --reveal' refuses
	// to decrypt/print the plaintext regardless of the flag. Deliberately
	// its own env var, not CONFIGCTL_NO_REVEAL — these are two independent
	// tools that happen to share internals, and a kill switch that only
	// half-applies because the caller set the other tool's variable is
	// worse than no kill switch at all.
	envNoReveal = "VAULTCTL_NO_REVEAL"
)
