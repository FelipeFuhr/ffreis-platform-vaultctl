package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func backupExportStore(secrets []*store.Item) store.Store {
	return fakeStore{
		listFn: func(_ context.Context, _, _ string, itemType store.ItemType) ([]*store.Item, error) {
			if itemType == store.ItemTypeSecret {
				return secrets, nil
			}
			return nil, nil
		},
	}
}

func TestRunBackupExport_WritesFileWithTierInMetadata(t *testing.T) {
	t.Parallel()

	item := encryptedVaultItem("root", "prod", "master-key", "value")
	st := backupExportStore([]*store.Item{item})

	var writtenPath string
	var writtenData []byte
	writeFile := func(path string, data []byte, _ os.FileMode) error {
		writtenPath, writtenData = path, data
		return nil
	}

	var out bytes.Buffer
	err := runBackupExport(context.Background(), st, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "root", env: "prod", outputPath: "/tmp/vault-root-prod.json", includeSecrets: true,
	}, writeFile, noopChmod, "tester-arn", &out)
	if err != nil {
		t.Fatalf("runBackupExport() error = %v", err)
	}
	if writtenPath != "/tmp/vault-root-prod.json" {
		t.Fatalf("writeFile path = %q, want /tmp/vault-root-prod.json", writtenPath)
	}

	var bf backup.BackupFile
	if err := json.Unmarshal(writtenData, &bf); err != nil {
		t.Fatalf("unmarshal written backup: %v", err)
	}
	if bf.Metadata.Tier != "root" {
		t.Errorf("Metadata.Tier = %q, want root", bf.Metadata.Tier)
	}
	if bf.Metadata.Environment != "prod" {
		t.Errorf("Metadata.Environment = %q, want prod", bf.Metadata.Environment)
	}
	if bf.Metadata.Project != vaultProject {
		t.Errorf("Metadata.Project = %q, want %q", bf.Metadata.Project, vaultProject)
	}
	if len(bf.Items) != 1 {
		t.Fatalf("Items = %d, want 1", len(bf.Items))
	}
	if bf.Items[0].Value == "value" {
		t.Fatal("exported item must carry ciphertext, not plaintext")
	}
	if strings.Contains(out.String(), "value") {
		t.Fatalf("plaintext leaked to vaultctl's own stdout: %q", out.String())
	}
}

// TestRunBackupExport_CorrectsPreExistingLoosePermissions is backup export's
// analogue of export-env's identically-named test: os.WriteFile never
// corrects an existing file's mode, so a stale --output file left over at a
// looser permission must have its mode actively corrected to 0600, not
// silently inherited. Uses the real os.WriteFile/os.Chmod, not fakes.
func TestRunBackupExport_CorrectsPreExistingLoosePermissions(t *testing.T) {
	item := encryptedVaultItem("root", "prod", "master-key", "value")
	st := backupExportStore([]*store.Item{item})

	dir := t.TempDir()
	path := dir + "/backup.json"
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed pre-existing file: %v", err)
	}

	var out bytes.Buffer
	err := runBackupExport(context.Background(), st, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "root", env: "prod", outputPath: path, includeSecrets: true,
	}, os.WriteFile, os.Chmod, "tester", &out)
	if err != nil {
		t.Fatalf("runBackupExport() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("exported file mode = %o, want 0600 — a pre-existing looser mode must be corrected, not inherited", info.Mode().Perm())
	}
}

func TestRunBackupExport_WithoutIncludeSecretsDoesNotRequireSecretKey(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, "" /* no secret key */, backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json", includeSecrets: false,
	}, func(string, []byte, os.FileMode) error { return nil }, noopChmod, "tester", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runBackupExport() error = %v, want nil — no secret key needed without --include-secrets", err)
	}
}

func TestRunBackupExport_IncludeSecretsRequiresSecretKey(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, "", backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json", includeSecrets: true,
	}, func(string, []byte, os.FileMode) error { return nil }, noopChmod, "tester", &bytes.Buffer{})
	if err == nil {
		t.Fatal("runBackupExport() error = nil, want error requiring a secret key with --include-secrets")
	}
}

func TestRunBackupExport_WriteFileErrorPropagates(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json",
	}, func(string, []byte, os.FileMode) error { return errTest("disk full") }, noopChmod, "tester", &bytes.Buffer{})
	if err == nil {
		t.Fatal("runBackupExport() error = nil, want error propagated from writeFile")
	}
}

// TestNewBackupExportCmd_InvalidTierFailsBeforeAnyNetworkCall exercises the
// real cobra Execute() path (not a direct runBackupExport call) so the
// RunE closure's own openStore-error branch — otherwise the one line in
// this package gremlins mutation testing found uncovered — is actually
// exercised, matching the same pattern already used for get/put/exec/
// export-env/list/delete's own "invalid tier fails before any network call"
// tests.
func TestNewBackupExportCmd_InvalidTierFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newBackupExportCmd(&deps{})
	cmd.SetArgs([]string{"--tier", "bogus", "--output", "/tmp/out.json", "--env", "dev"})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for an invalid tier")
	}
}

// TestNewBackupExportCmd_ReachesRunBackupExportOnValidTier is backup
// export's analogue of delete/list's identically-purposed test: a valid
// tier clears openStore (no network call — see openStore's own doc), so
// RunE reaches its final `return runBackupExport(...)` line; the exporter's
// own store.List then fails fast against the unreachable endpoint instead
// of reaching real AWS. Without this, that line — the only place RunE is
// wired to the real os.WriteFile/os.Chmod — went uncovered even though
// every other command already had its valid-tier continuation covered.
func TestNewBackupExportCmd_ReachesRunBackupExportOnValidTier(t *testing.T) {
	t.Parallel()

	d := &deps{awsCfg: unreachableAWSConfig()}
	cmd := newBackupExportCmd(d)
	cmd.SetArgs([]string{"--tier", "identity", "--output", "/tmp/out.json", "--env", "dev"})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error from the unreachable store")
	}
}

func TestNewBackupExportCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newBackupExportCmd(&deps{})
	if cmd.Use != "export" {
		t.Errorf("Use = %q, want export", cmd.Use)
	}
	for _, name := range []string{"tier", "env", "output", "include-secrets"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
}
