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
	}, writeFile, "tester-arn", &out)
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

func TestRunBackupExport_WithoutIncludeSecretsDoesNotRequireSecretKey(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, "" /* no secret key */, backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json", includeSecrets: false,
	}, func(string, []byte, os.FileMode) error { return nil }, "tester", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runBackupExport() error = %v, want nil — no secret key needed without --include-secrets", err)
	}
}

func TestRunBackupExport_IncludeSecretsRequiresSecretKey(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, "", backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json", includeSecrets: true,
	}, func(string, []byte, os.FileMode) error { return nil }, "tester", &bytes.Buffer{})
	if err == nil {
		t.Fatal("runBackupExport() error = nil, want error requiring a secret key with --include-secrets")
	}
}

func TestRunBackupExport_WriteFileErrorPropagates(t *testing.T) {
	t.Parallel()

	st := backupExportStore(nil)
	err := runBackupExport(context.Background(), st, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "identity", env: "dev", outputPath: "/tmp/out.json",
	}, func(string, []byte, os.FileMode) error { return errTest("disk full") }, "tester", &bytes.Buffer{})
	if err == nil {
		t.Fatal("runBackupExport() error = nil, want error propagated from writeFile")
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
