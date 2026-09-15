// Package vaulttier resolves vaultctl's <tier> argument to the DynamoDB
// table that backs it, and validates the <tier>/--env combination vaultctl
// requires on every command. Kept out of cmd/vaultctl so this — table
// selection and the AAD binding below — is unit- and mutation-tested as
// business logic, not left as untested cobra wiring.
package vaulttier

import (
	"errors"
	"fmt"
)

// The three tiers vaultctl manages. Each maps to its own DynamoDB table
// (ffreis-vault-<tier>-<env>) — a completely separate partition of storage,
// not a value within a shared table.
const (
	Identity = "identity"
	Repo     = "repo"
	Root     = "root"
)

// Envs vaultctl accepts. Deliberately just two: this vault has no "staging"
// or other environment, and --env takes no default specifically so an
// omitted flag can never silently resolve to prod (see TableName).
const (
	Dev  = "dev"
	Prod = "prod"
)

// tablePrefix is the fixed naming convention the vault's Terraform uses for
// all six tables: ffreis-vault-{identity,repo,root}-{dev,prod}.
const tablePrefix = "ffreis-vault-"

var validTiers = map[string]bool{Identity: true, Repo: true, Root: true}

var validEnvs = map[string]bool{Dev: true, Prod: true}

// ErrInvalidTier is returned when tier is not one of identity, repo, root.
var ErrInvalidTier = errors.New("tier must be one of: identity, repo, root")

// ErrInvalidEnv is returned when env is not exactly "dev" or "prod".
var ErrInvalidEnv = errors.New("--env must be exactly one of: dev, prod")

// ValidateTier reports whether tier is a recognised vault tier.
func ValidateTier(tier string) error {
	if !validTiers[tier] {
		return fmt.Errorf("%w (got %q)", ErrInvalidTier, tier)
	}
	return nil
}

// ValidateEnv reports whether env is a recognised vault environment.
func ValidateEnv(env string) error {
	if !validEnvs[env] {
		return fmt.Errorf("%w (got %q)", ErrInvalidEnv, env)
	}
	return nil
}

// TableName validates tier and env and resolves the DynamoDB table that
// backs them. The caller never passes a table name directly — this is the
// only place that constructs one, so the naming convention only has to be
// right in one place.
func TableName(tier, env string) (string, error) {
	if err := ValidateTier(tier); err != nil {
		return "", err
	}
	if err := ValidateEnv(env); err != nil {
		return "", err
	}
	return tablePrefix + tier + "-" + env, nil
}

// AADKey returns the composite key name to bind into a secret's encryption
// AAD (additional authenticated data) for a given tier+key.
//
// Collision safety depends on tier never containing "/": callers must pass a
// tier that has already gone through ValidateTier (as every vaultctl command
// does, via TableName in openStore) — one of exactly Identity/Repo/Root, none
// of which can collide with each other or with an arbitrary key string once
// joined by "/". Do not call this with an unvalidated tier.
//
// Every vaultctl-managed item uses the same hardcoded project ("vault") in
// its AAD, since this vault has no per-project dimension. Left at that alone,
// a secret named e.g. "github-pat" in the identity tier and a same-named
// secret in the root tier would derive IDENTICAL AAD (project+env+key all
// match) even though they live in physically different DynamoDB tables —
// meaning ciphertext copied from one tier's table into another tier's table
// under the same key name would decrypt successfully. That is exactly the
// ciphertext-transplant attack AAD exists to prevent (see AGENTS.md). Binding
// tier into the key-name component of the AAD closes that gap: the two
// same-named secrets in different tiers now bind to different AAD, so
// transplanting one tier's ciphertext into another tier's table under the
// same key fails to decrypt.
func AADKey(tier, key string) string {
	return tier + "/" + key
}
