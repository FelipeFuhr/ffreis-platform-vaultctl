package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/guard"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func TestRunGet_MaskedByDefaultButFingerprintAlways(t *testing.T) {
	t.Parallel()

	item := encryptedVaultItem("identity", "dev", "github-pat", "ghp_abc123")
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}

	var out bytes.Buffer
	err := runGet(context.Background(), st, testSecretKey, "identity", "github-pat", "dev", false, &out)
	if err != nil {
		t.Fatalf("runGet() error = %v", err)
	}
	if !strings.Contains(out.String(), "value:       ***") {
		t.Fatalf("output should mask value, got: %s", out.String())
	}
	if strings.Contains(out.String(), "ghp_abc123") {
		t.Fatalf("plaintext must never appear in metadata-only output, got: %s", out.String())
	}
	wantFingerprint := guard.Fingerprint([]byte("ghp_abc123"))
	if !strings.Contains(out.String(), "fingerprint: "+wantFingerprint) {
		t.Fatalf("output missing expected fingerprint %q, got: %s", wantFingerprint, out.String())
	}
}

func TestRunGet_Reveal(t *testing.T) {
	t.Parallel()

	item := encryptedVaultItem("root", "prod", "master-key", "top-secret-value")
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}

	var out bytes.Buffer
	err := runGet(context.Background(), st, testSecretKey, "root", "master-key", "prod", true, &out)
	if err != nil {
		t.Fatalf("runGet() error = %v", err)
	}
	if !strings.Contains(out.String(), "top-secret-value") {
		t.Fatalf("--reveal should print the plaintext, got: %s", out.String())
	}
}

// TestRunGet_RevealRefusedUnderNoRevealKillSwitch is the vaultctl analogue
// of platform-configctl's CONFIGCTL_NO_REVEAL proof, under vaultctl's own
// independent env var.
func TestRunGet_RevealRefusedUnderNoRevealKillSwitch(t *testing.T) {
	t.Setenv(envNoReveal, "1")

	item := encryptedVaultItem("identity", "dev", "k", "value")
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}

	var out bytes.Buffer
	err := runGet(context.Background(), st, testSecretKey, "identity", "k", "dev", true, &out)
	if err == nil {
		t.Fatal("runGet() error = nil, want error refusing --reveal under VAULTCTL_NO_REVEAL")
	}
	if !strings.Contains(err.Error(), envNoReveal) {
		t.Errorf("error should name %s, got: %v", envNoReveal, err)
	}
	if strings.Contains(out.String(), "value") {
		t.Fatalf("plaintext must not leak even in the refused-reveal error path, got: %s", out.String())
	}
}

func TestRunGet_NoRevealKillSwitchDoesNotAffectMaskedGet(t *testing.T) {
	t.Setenv(envNoReveal, "1")

	item := encryptedVaultItem("identity", "dev", "k", "value")
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}

	var out bytes.Buffer
	// reveal=false: the kill switch only gates --reveal's print path.
	if err := runGet(context.Background(), st, testSecretKey, "identity", "k", "dev", false, &out); err != nil {
		t.Fatalf("runGet() error = %v, want nil — masked get must still work under the kill switch", err)
	}
}

func TestRunGet_MissingSecretKey(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var out bytes.Buffer
	err := runGet(context.Background(), st, "", "identity", "k", "dev", false, &out)
	if err == nil {
		t.Fatal("runGet() error = nil, want error for missing secret key")
	}
}

func TestRunGet_NotFound(t *testing.T) {
	t.Parallel()

	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return nil, store.ErrNotFound
	}}
	var out bytes.Buffer
	err := runGet(context.Background(), st, testSecretKey, "identity", "missing", "dev", false, &out)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != exitNotFound {
		t.Fatalf("runGet() error = %v, want *ExitError{Code: exitNotFound}", err)
	}
}

// TestRunGet_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase
// deliberately triggers a decrypt failure via a wrong VAULTCTL_SECRET_KEY
// and inspects the FULL error string (not just its type) to confirm neither
// the plaintext nor either passphrase ever appears in it.
func TestRunGet_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-get-must-never-leak-in-error-text"
	const wrongKey = "98765432109876543210987654321098"
	item := encryptedVaultItem("identity", "dev", "github-pat", plaintext)
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}

	var out bytes.Buffer
	err := runGet(context.Background(), st, wrongKey, "identity", "github-pat", "dev", true, &out)
	if err == nil {
		t.Fatal("runGet() error = nil, want decrypt failure under a wrong passphrase")
	}
	full := err.Error()
	for _, sensitive := range []string{plaintext, testSecretKey, wrongKey} {
		if strings.Contains(full, sensitive) {
			t.Fatalf("decrypt-failure error text leaked a sensitive value %q: %q", sensitive, full)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("vaultctl's own stdout must stay empty on decrypt failure, got: %q", out.String())
	}
}

// TestRunGet_TierBoundAADRejectsCrossTierCiphertext proves the AAD fix: a
// ciphertext encrypted under one tier's AAD does not decrypt as if it were
// the SAME key name in a different tier, even with the identical passphrase,
// env, and key — the transplant this vaulttier.AADKey binding exists to
// prevent.
func TestRunGet_TierBoundAADRejectsCrossTierCiphertext(t *testing.T) {
	t.Parallel()

	// Encrypted under "repo", but the store item is returned to a "get" call
	// made against "identity" — simulating a cross-tier ciphertext copy.
	const plaintext = "value-that-must-not-survive-a-transplant"
	repoItem := encryptedVaultItem("repo", "dev", "shared-name", plaintext)
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return repoItem, nil
	}}

	var out bytes.Buffer
	err := runGet(context.Background(), st, testSecretKey, "identity", "shared-name", "dev", true, &out)
	if err == nil {
		t.Fatal("runGet() error = nil, want decrypt failure — ciphertext transplanted across tiers must not decrypt")
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatalf("cross-tier decrypt-failure error text leaked the plaintext: %q", err.Error())
	}
	if out.Len() != 0 {
		t.Fatalf("vaultctl's own stdout must stay empty when a transplanted ciphertext fails to decrypt, got: %q", out.String())
	}
}

func TestNewGetCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newGetCmd(&deps{})
	if !strings.HasPrefix(cmd.Use, "get <tier> <key>") {
		t.Errorf("Use = %q, want prefix %q", cmd.Use, "get <tier> <key>")
	}
	for _, name := range []string{"env", "reveal"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if cmd.Args == nil {
		t.Fatal("Args validator is nil")
	}
}
