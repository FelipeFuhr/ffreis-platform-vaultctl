package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// writeBackupFile builds and writes a valid, sealed backup.BackupFile with
// the given tier/env in its metadata, exactly as 'backup export' would.
func writeBackupFile(t *testing.T, tier, env string, items []backup.BackupItem) string {
	t.Helper()

	bf := backup.NewBackupFile(vaultProject, env, "test", "tester")
	bf.Metadata.Tier = tier
	bf.Items = items
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRunBackupImport_ResolvesTableFromFileMetadata(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, "repo", "dev", []backup.BackupItem{
		{Key: "a", Value: "ciphertext-a", ItemType: string(store.ItemTypeSecret), Checksum: "sha256:x"},
	})

	var gotTier, gotEnv string
	var setCount int
	openFn := func(tier, env string) (store.Store, string, error) {
		gotTier, gotEnv = tier, env
		return fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
			setFn: func(context.Context, *store.Item) error {
				setCount++
				return nil
			},
		}, "ffreis-vault-repo-dev", nil
	}

	err := runBackupImport(context.Background(), path, backup.ImportOptions{}, noopLogger{}, openFn)
	if err != nil {
		t.Fatalf("runBackupImport() error = %v", err)
	}
	if gotTier != "repo" || gotEnv != "dev" {
		t.Fatalf("openStoreFn called with tier=%q env=%q, want repo/dev (from the file's own metadata)", gotTier, gotEnv)
	}
	if setCount != 1 {
		t.Fatalf("store.Set called %d times, want 1", setCount)
	}
}

// TestRunBackupImport_MaliciousTierEditCausesTransplantedCiphertextToFailDecryption
// is the real, end-to-end proof of the cross-tier transplant protection
// through the ACTUAL backup export -> malicious edit -> import -> get
// pipeline — not just the isolated AADKey/runGet-level unit tests
// elsewhere. It builds a backup item genuinely encrypted under tier "repo",
// then constructs a backup file whose Metadata.Tier lies and claims
// "identity" (exactly what an attacker editing an exported JSON file before
// handing it to `backup import` would do), imports it, and confirms a
// SUBSEQUENT `get identity <key>` against the table the malicious import
// wrote to fails to decrypt — proving the AAD tier binding, not merely a
// round-trip of the tier field, is what actually stops the attack.
func TestRunBackupImport_MaliciousTierEditCausesTransplantedCiphertextToFailDecryption(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-transplant-must-fail-to-decrypt"
	// Genuinely encrypted under tier "repo" (AAD bound to "repo/shared-key").
	repoItem := encryptedVaultItem("repo", "dev", "shared-key", plaintext)

	// The malicious edit: this backup file's own Metadata.Tier claims
	// "identity" even though the ciphertext it carries was sealed under
	// "repo".
	path := writeBackupFile(t, "identity", "dev", []backup.BackupItem{
		{
			Key: repoItem.Key, Value: repoItem.Value, KeyID: repoItem.KeyID,
			ItemType: string(store.ItemTypeSecret), Checksum: "sha256:x",
		},
	})

	var imported *store.Item
	openFn := func(tier, env string) (store.Store, string, error) {
		if tier != "identity" || env != "dev" {
			t.Fatalf("openFn called with tier=%q env=%q, want identity/dev (the file's edited metadata)", tier, env)
		}
		return fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
			setFn: func(_ context.Context, item *store.Item) error {
				imported = item
				return nil
			},
		}, "ffreis-vault-identity-dev", nil
	}

	if err := runBackupImport(context.Background(), path, backup.ImportOptions{}, noopLogger{}, openFn); err != nil {
		t.Fatalf("runBackupImport() error = %v — import itself must succeed here (it never decrypts anything); "+
			"the transplant is only caught at the NEXT decrypt attempt", err)
	}
	if imported == nil {
		t.Fatal("store.Set was never called — the malicious import did not actually write the transplanted ciphertext")
	}

	// A subsequent operator now runs `vaultctl get identity shared-key`
	// against the table the malicious import just wrote to. This MUST fail:
	// the ciphertext's AAD is bound to "repo/shared-key", not
	// "identity/shared-key", so decryption must not succeed even though
	// tier, env, key, and passphrase all line up from the caller's side.
	getStore := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return imported, nil
	}}
	var out bytes.Buffer
	err := runGet(context.Background(), getStore, testSecretKey, "identity", "shared-key", "dev", true, &out)
	if err == nil {
		t.Fatal("runGet() after the malicious import succeeded, want decrypt failure — the AAD tier binding did not stop the transplant")
	}
	if strings.Contains(err.Error(), plaintext) || strings.Contains(out.String(), plaintext) {
		t.Fatalf("plaintext leaked despite the failed transplant decrypt: error=%q stdout=%q", err.Error(), out.String())
	}
}

func TestRunBackupImport_DryRunWritesNothing(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, "identity", "prod", []backup.BackupItem{
		{Key: "a", Value: "ciphertext-a", ItemType: string(store.ItemTypeSecret), Checksum: "sha256:x"},
	})

	var setCalled bool
	openFn := func(string, string) (store.Store, string, error) {
		return fakeStore{
			setFn: func(context.Context, *store.Item) error {
				setCalled = true
				return nil
			},
		}, "table", nil
	}

	err := runBackupImport(context.Background(), path, backup.ImportOptions{DryRun: true}, noopLogger{}, openFn)
	if err != nil {
		t.Fatalf("runBackupImport() error = %v", err)
	}
	if setCalled {
		t.Fatal("--dry-run must not write to the store")
	}
}

func TestRunBackupImport_InvalidTierInMetadataIsError(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, "not-a-real-tier", "dev", nil)

	openFn := func(tier, env string) (store.Store, string, error) {
		return nil, "", errTest("invalid tier: " + tier)
	}

	if err := runBackupImport(context.Background(), path, backup.ImportOptions{}, noopLogger{}, openFn); err == nil {
		t.Fatal("runBackupImport() error = nil, want error for an invalid tier in the file's metadata")
	}
}

func TestRunBackupImport_MissingFileIsError(t *testing.T) {
	t.Parallel()

	openFn := func(string, string) (store.Store, string, error) {
		t.Fatal("openStoreFn should not be called before the file is even read")
		return nil, "", nil
	}
	err := runBackupImport(context.Background(), "/nonexistent/path.json", backup.ImportOptions{}, noopLogger{}, openFn)
	if err == nil {
		t.Fatal("runBackupImport() error = nil, want error for a missing file")
	}
}

func TestRunBackupImport_MalformedJSONIsError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	openFn := func(string, string) (store.Store, string, error) {
		t.Fatal("openStoreFn should not be called for an unparseable file")
		return nil, "", nil
	}
	if err := runBackupImport(context.Background(), path, backup.ImportOptions{}, noopLogger{}, openFn); err == nil {
		t.Fatal("runBackupImport() error = nil, want error for malformed JSON")
	}
}

func TestNewBackupImportCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newBackupImportCmd(&deps{})
	if cmd.Use != "import" {
		t.Errorf("Use = %q, want import", cmd.Use)
	}
	for _, name := range []string{"input", "dry-run", "overwrite"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	// Deliberately no --tier/--env — see the command's Long help.
	for _, name := range []string{"tier", "env"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Errorf("flag --%s should not exist on backup import", name)
		}
	}
}
