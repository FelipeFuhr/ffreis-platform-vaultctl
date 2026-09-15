package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
