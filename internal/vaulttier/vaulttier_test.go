package vaulttier

import (
	"errors"
	"testing"
)

func TestTableName_ValidCombinations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		tier, env, want string
	}{
		{Identity, Dev, "ffreis-vault-identity-dev"},
		{Identity, Prod, "ffreis-vault-identity-prod"},
		{Repo, Dev, "ffreis-vault-repo-dev"},
		{Repo, Prod, "ffreis-vault-repo-prod"},
		{Root, Dev, "ffreis-vault-root-dev"},
		{Root, Prod, "ffreis-vault-root-prod"},
	}
	for _, tc := range cases {
		got, err := TableName(tc.tier, tc.env)
		if err != nil {
			t.Fatalf("TableName(%q, %q) error = %v", tc.tier, tc.env, err)
		}
		if got != tc.want {
			t.Errorf("TableName(%q, %q) = %q, want %q", tc.tier, tc.env, got, tc.want)
		}
	}
}

func TestTableName_RejectsInvalidTier(t *testing.T) {
	t.Parallel()

	for _, tier := range []string{"", "Identity", "IDENTITY", "identity ", "project", "vault", "admin"} {
		_, err := TableName(tier, Dev)
		if !errors.Is(err, ErrInvalidTier) {
			t.Errorf("TableName(%q, dev) error = %v, want ErrInvalidTier", tier, err)
		}
	}
}

func TestTableName_RejectsInvalidEnv(t *testing.T) {
	t.Parallel()

	for _, env := range []string{"", "staging", "Dev", "PROD", "production", "development"} {
		_, err := TableName(Identity, env)
		if !errors.Is(err, ErrInvalidEnv) {
			t.Errorf("TableName(identity, %q) error = %v, want ErrInvalidEnv", env, err)
		}
	}
}

func TestTableName_EmptyEnvIsRejectedNotDefaulted(t *testing.T) {
	t.Parallel()

	// The whole point of requiring --env explicitly is that an omitted flag
	// must never silently resolve to any table — prod included. Confirm an
	// empty env string (what an unset, non-required flag would leave behind)
	// is rejected rather than falling back to any table name.
	_, err := TableName(Root, "")
	if err == nil {
		t.Fatal("TableName(root, \"\") error = nil, want error — empty --env must never resolve to a table")
	}
}

func TestValidateTier(t *testing.T) {
	t.Parallel()

	for _, tier := range []string{Identity, Repo, Root} {
		if err := ValidateTier(tier); err != nil {
			t.Errorf("ValidateTier(%q) error = %v, want nil", tier, err)
		}
	}
	if err := ValidateTier("bogus"); !errors.Is(err, ErrInvalidTier) {
		t.Errorf("ValidateTier(bogus) error = %v, want ErrInvalidTier", err)
	}
}

func TestAADKey_DiffersAcrossTiersForSameKey(t *testing.T) {
	t.Parallel()

	identity := AADKey(Identity, "github-pat")
	repo := AADKey(Repo, "github-pat")
	root := AADKey(Root, "github-pat")

	if identity == repo || identity == root || repo == root {
		t.Fatalf("AADKey must differ across tiers for the same key name (transplant protection): "+
			"identity=%q repo=%q root=%q", identity, repo, root)
	}
}

func TestAADKey_StableForSameTierAndKey(t *testing.T) {
	t.Parallel()

	a := AADKey(Identity, "stripe-key")
	b := AADKey(Identity, "stripe-key")
	if a != b {
		t.Fatalf("AADKey(identity, stripe-key) is not stable: %q != %q", a, b)
	}
}
