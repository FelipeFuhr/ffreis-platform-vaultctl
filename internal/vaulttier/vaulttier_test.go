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

	for _, tier := range []string{"", "Identity", "IDENTITY", "identity ", " identity", "project", "vault", "admin"} {
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
	// Case-variants and whitespace-padded variants of a valid tier name must
	// be REJECTED, not silently normalized to the canonical form — a caller
	// that typoed "Identity" must get a clear error, never a quiet fallback
	// to the identity tier.
	for _, tier := range []string{"bogus", "Identity", "IDENTITY", " identity", "identity "} {
		if err := ValidateTier(tier); !errors.Is(err, ErrInvalidTier) {
			t.Errorf("ValidateTier(%q) error = %v, want ErrInvalidTier", tier, err)
		}
	}
}

// TestValidateEnv directly exercises ValidateEnv (not just indirectly via
// TableName) and confirms case-variants and whitespace-padded variants of a
// valid env are rejected outright rather than normalized — the same
// discipline as ValidateTier, and for the same reason: --env has no default
// specifically so nothing about it should ever resolve silently.
func TestValidateEnv(t *testing.T) {
	t.Parallel()

	for _, env := range []string{Dev, Prod} {
		if err := ValidateEnv(env); err != nil {
			t.Errorf("ValidateEnv(%q) error = %v, want nil", env, err)
		}
	}
	for _, env := range []string{"", "Dev", "DEV", " dev", "dev ", "PROD", "staging"} {
		if err := ValidateEnv(env); !errors.Is(err, ErrInvalidEnv) {
			t.Errorf("ValidateEnv(%q) error = %v, want ErrInvalidEnv", env, err)
		}
	}
}

// TestAADKey_UnvalidatedTierContainingSlashCanCollide documents, with a real
// assertion rather than only a comment, exactly the constraint AADKey's own
// doc warns about: collision safety depends on tier having already gone
// through ValidateTier. Every real vaultctl command path satisfies that (via
// openStore's TableName call before AADKey is ever reached), but AADKey
// itself has no way to enforce it — it is a plain string join. If a tier
// value containing "/" ever reached AADKey unvalidated (e.g. a future
// refactor that calls encryptVaultValue/decryptVaultItem directly, bypassing
// openStore), two DIFFERENT logical tier/key pairs derive the IDENTICAL AAD,
// which is precisely the ciphertext-transplant collision the tier-binding
// fix exists to prevent. This test proves that collision is real, not
// hypothetical, so the doc comment's warning is backed by an actual failure
// mode rather than trusted on faith.
func TestAADKey_UnvalidatedTierContainingSlashCanCollide(t *testing.T) {
	t.Parallel()

	maliciousTier := AADKey("root", "x/y") // tier="root", key contains "/"
	otherRealTier := AADKey("root/x", "y") // an (invalid) tier already containing "/"
	if maliciousTier != otherRealTier {
		t.Fatalf("expected AADKey(%q, %q) to collide with AADKey(%q, %q) when tier is unvalidated, got %q != %q — "+
			"if this ever stops colliding, double check AADKey's doc comment is still accurate",
			"root", "x/y", "root/x", "y", maliciousTier, otherRealTier)
	}
	// The collision only matters for a tier that ValidateTier would have
	// rejected in the first place — confirm "root/x" is indeed invalid, so
	// this test is documenting a real precondition, not a reachable one.
	if err := ValidateTier("root/x"); !errors.Is(err, ErrInvalidTier) {
		t.Fatalf(`ValidateTier("root/x") error = %v, want ErrInvalidTier (this collision is only possible when tier `+
			`validation is skipped)`, err)
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
