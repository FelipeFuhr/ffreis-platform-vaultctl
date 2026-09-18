//go:build integration

// Integration coverage for vaultctl's command layer against a REAL DynamoDB
// (DynamoDB Local), not a fake — proving get/put/list/delete/backup
// round-trip through the actual Store implementation and conditional
// writes, the same rigor platform-configctl's own
// secret_rotate_integration_test.go applies.
//
// Run with: make test-integration (starts DynamoDB Local via podman)
// Or point DYNAMODB_ENDPOINT at an already-running instance.
// Skipped entirely when no endpoint is reachable, so `go test ./...` stays
// green on a machine without a container runtime.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"

	"github.com/ffreis/platform-vaultctl/internal/vaulttier"
)

const defaultDDBEndpoint = "http://localhost:8000"

func ddbEndpoint() string {
	if v := os.Getenv("DYNAMODB_ENDPOINT"); v != "" {
		return v
	}
	return defaultDDBEndpoint
}

func newIntegrationClient(t *testing.T) *dynamodb.Client {
	t.Helper()

	endpoint := ddbEndpoint()
	host := endpoint
	for _, prefix := range []string{"http://", "https://"} {
		if len(host) > len(prefix) && host[:len(prefix)] == prefix {
			host = host[len(prefix):]
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		t.Skipf("DynamoDB Local not reachable at %s (%v) — run `make test-integration`", endpoint, err)
	}
	_ = conn.Close()

	return dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: awssdk.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
}

// newIntegrationTable creates a throwaway table with the real PK/SK schema
// (the same schema Terraform gives every ffreis-vault-<tier>-<env> table)
// and removes it when the test ends.
func newIntegrationTable(t *testing.T, client *dynamodb.Client) string {
	t.Helper()

	name := fmt.Sprintf("vaultctl-it-%s-%d", t.Name(), time.Now().UnixNano())
	safe := make([]rune, 0, len(name))
	for _, r := range name {
		if r == '/' || r == ' ' {
			r = '-'
		}
		safe = append(safe, r)
	}
	name = string(safe)

	ctx := context.Background()
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: awssdk.String(name),
		AttributeDefinitions: []ddbtypes.AttributeDefinition{
			{AttributeName: awssdk.String("PK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: awssdk.String("SK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []ddbtypes.KeySchemaElement{
			{AttributeName: awssdk.String("PK"), KeyType: ddbtypes.KeyTypeHash},
			{AttributeName: awssdk.String("SK"), KeyType: ddbtypes.KeyTypeRange},
		},
		BillingMode: ddbtypes.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatalf("CreateTable(%s): %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: awssdk.String(name)})
	})
	return name
}

// newRealTierTable creates the REAL, production-named table for tier+env
// (via vaulttier.TableName — the exact same resolution openStore uses, not
// an ad-hoc throwaway name) and removes it when the test ends. Used by
// tests that need to prove tier isolation itself, where a single
// arbitrarily-named throwaway table (as newIntegrationTable creates) cannot
// exercise the actual per-tier table separation.
func newRealTierTable(t *testing.T, client *dynamodb.Client, tier, env string) store.Store {
	t.Helper()

	table, err := vaulttier.TableName(tier, env)
	if err != nil {
		t.Fatalf("vaulttier.TableName(%q, %q): %v", tier, env, err)
	}

	ctx := context.Background()
	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: awssdk.String(table),
		AttributeDefinitions: []ddbtypes.AttributeDefinition{
			{AttributeName: awssdk.String("PK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: awssdk.String("SK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []ddbtypes.KeySchemaElement{
			{AttributeName: awssdk.String("PK"), KeyType: ddbtypes.KeyTypeHash},
			{AttributeName: awssdk.String("SK"), KeyType: ddbtypes.KeyTypeRange},
		},
		BillingMode: ddbtypes.BillingModePayPerRequest,
	})
	var inUse *ddbtypes.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		t.Fatalf("CreateTable(%s): %v", table, err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: awssdk.String(table)})
	})
	return store.NewDynamoStore(client, table)
}

func newIntegrationStore(t *testing.T) store.Store {
	t.Helper()
	client := newIntegrationClient(t)
	table := newIntegrationTable(t, client)
	return store.NewDynamoStore(client, table)
}

// TestIntegrationPutThenGet_RoundTripsThroughRealStore proves put -> get
// round-trips a real secret through the real command layer and real
// AES-256-GCM crypto (not a fake), the way an operator would use it.
func TestIntegrationPutThenGet_RoundTripsThroughRealStore(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	if err := runPut(ctx, st, noopLogger{}, testSecretKey, "identity", "github-pat", "dev", "tester",
		strings.NewReader("ghp_live_abc123")); err != nil {
		t.Fatalf("runPut: %v", err)
	}

	var out bytes.Buffer
	if err := runGet(ctx, st, testSecretKey, "identity", "github-pat", "dev", true, &out); err != nil {
		t.Fatalf("runGet: %v", err)
	}
	if !strings.Contains(out.String(), "ghp_live_abc123") {
		t.Fatalf("get --reveal output missing plaintext, got: %s", out.String())
	}
}

// TestIntegrationPut_IsIdempotentOnVersionAndPreservesCreatedAt verifies a
// second put against the same key carries the existing version forward,
// exercising the real conditional-write path (not a fake that can't
// reproduce it).
func TestIntegrationPut_CarriesVersionAcrossWrites(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	if err := runPut(ctx, st, noopLogger{}, testSecretKey, "repo", "k", "dev", "tester", strings.NewReader("v1")); err != nil {
		t.Fatalf("first runPut: %v", err)
	}
	first, err := st.Get(ctx, vaultProject, "dev", store.ItemTypeSecret, "k")
	if err != nil {
		t.Fatalf("Get after first put: %v", err)
	}

	if err := runPut(ctx, st, noopLogger{}, testSecretKey, "repo", "k", "dev", "tester", strings.NewReader("v2")); err != nil {
		t.Fatalf("second runPut: %v", err)
	}
	second, err := st.Get(ctx, vaultProject, "dev", store.ItemTypeSecret, "k")
	if err != nil {
		t.Fatalf("Get after second put: %v", err)
	}

	if second.Version != first.Version+1 {
		t.Fatalf("Version = %d, want %d (exactly one write bumped it)", second.Version, first.Version+1)
	}
}

// TestIntegrationList_ReflectsRealWrites proves list reads back what put
// wrote, through the real store.
func TestIntegrationList_ReflectsRealWrites(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	for _, key := range []string{"a", "b", "c"} {
		if err := runPut(ctx, st, noopLogger{}, testSecretKey, "root", key, "prod", "tester", strings.NewReader("v-"+key)); err != nil {
			t.Fatalf("runPut(%s): %v", key, err)
		}
	}

	var out bytes.Buffer
	if err := runList(ctx, st, "prod", &out); err != nil {
		t.Fatalf("runList: %v", err)
	}
	for _, key := range []string{"a", "b", "c"} {
		if !strings.Contains(out.String(), key+"=***") {
			t.Errorf("list output missing %s=***, got: %s", key, out.String())
		}
	}
}

// TestIntegrationDelete_RemovesFromRealStore proves delete against the real
// store, and that a subsequent get reports not-found.
func TestIntegrationDelete_RemovesFromRealStore(t *testing.T) {
	st := newIntegrationStore(t)
	ctx := context.Background()

	if err := runPut(ctx, st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", strings.NewReader("v")); err != nil {
		t.Fatalf("runPut: %v", err)
	}
	if err := runDelete(ctx, st, noopLogger{}, "identity", "k", "dev"); err != nil {
		t.Fatalf("runDelete: %v", err)
	}

	var out bytes.Buffer
	err := runGet(ctx, st, testSecretKey, "identity", "k", "dev", false, &out)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != exitNotFound {
		t.Fatalf("get after delete: error = %v, want ExitError{Code: exitNotFound}", err)
	}
}

// TestIntegrationBackupExportThenImport_RoundTripsCiphertext proves export
// writes real ciphertext for a real item, and import (against a SEPARATE
// throwaway table, resolved purely from the file's own metadata.tier, via
// the injected openStoreFn) writes it back — the vault's stated recovery
// path.
func TestIntegrationBackupExportThenImport_RoundTripsCiphertext(t *testing.T) {
	srcClient := newIntegrationClient(t)
	srcTable := newIntegrationTable(t, srcClient)
	srcStore := store.NewDynamoStore(srcClient, srcTable)
	ctx := context.Background()

	if err := runPut(ctx, srcStore, noopLogger{}, testSecretKey, "root", "master-key", "prod", "tester",
		strings.NewReader("s3cr3t-root-value")); err != nil {
		t.Fatalf("seed runPut: %v", err)
	}

	dir := t.TempDir()
	outPath := dir + "/export.json"
	var exportOut bytes.Buffer
	err := runBackupExport(ctx, srcStore, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "root", env: "prod", outputPath: outPath, includeSecrets: true,
	}, os.WriteFile, os.Chmod, "tester", &exportOut)
	if err != nil {
		t.Fatalf("runBackupExport: %v", err)
	}

	// Import into a SEPARATE throwaway table, standing in for
	// ffreis-vault-root-prod, reached only via the file's own
	// metadata.tier/metadata.environment (openFn ignores whatever it's
	// asked for and always returns the destination table, simulating
	// "the file's metadata resolved to the right physical table").
	dstClient := newIntegrationClient(t)
	dstTable := newIntegrationTable(t, dstClient)
	dstStore := store.NewDynamoStore(dstClient, dstTable)
	openFn := func(tier, env string) (store.Store, string, error) {
		if tier != "root" || env != "prod" {
			t.Fatalf("openFn called with tier=%q env=%q, want root/prod (from the file's own metadata)", tier, env)
		}
		return dstStore, dstTable, nil
	}

	if err := runBackupImport(ctx, outPath, backup.ImportOptions{Overwrite: true}, noopLogger{}, openFn); err != nil {
		t.Fatalf("runBackupImport: %v", err)
	}

	var out bytes.Buffer
	if err := runGet(ctx, dstStore, testSecretKey, "root", "master-key", "prod", true, &out); err != nil {
		t.Fatalf("runGet against imported table: %v", err)
	}
	if !strings.Contains(out.String(), "s3cr3t-root-value") {
		t.Fatalf("imported secret did not round-trip, got: %s", out.String())
	}
}

// TestIntegrationBackupImport_MaliciousTierEditFailsToDecryptAfterImport is
// the real-DynamoDB analogue of the fake-store unit test with the same
// purpose (see backup_import_test.go). It runs the ACTUAL export -> edit ->
// import -> get pipeline against DynamoDB Local: export a real item from a
// real "repo" tier table, tamper with the exported file's Metadata.Tier to
// claim "identity", import it into a real "identity" tier table, and prove
// a subsequent get against that table fails to decrypt — the AAD tier
// binding surviving a real store round-trip, not just an in-memory fake.
func TestIntegrationBackupImport_MaliciousTierEditFailsToDecryptAfterImport(t *testing.T) {
	client := newIntegrationClient(t)
	repoStore := newRealTierTable(t, client, "repo", "dev")
	ctx := context.Background()

	const plaintext = "s3cr3t-real-transplant-must-fail"
	if err := runPut(ctx, repoStore, noopLogger{}, testSecretKey, "repo", "shared-key", "dev", "tester",
		strings.NewReader(plaintext)); err != nil {
		t.Fatalf("seed runPut: %v", err)
	}

	dir := t.TempDir()
	exportPath := dir + "/export.json"
	var exportOut bytes.Buffer
	if err := runBackupExport(ctx, repoStore, noopLogger{}, testSecretKey, backupExportOpts{
		tier: "repo", env: "dev", outputPath: exportPath, includeSecrets: true,
	}, os.WriteFile, os.Chmod, "tester", &exportOut); err != nil {
		t.Fatalf("runBackupExport: %v", err)
	}

	// The malicious edit: rewrite the exported file's own Metadata.Tier from
	// "repo" to "identity", leaving every item's ciphertext untouched.
	raw, err := os.ReadFile(exportPath) //nolint:gosec // fixed test-owned path under t.TempDir()
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var bf backup.BackupFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		t.Fatalf("unmarshal exported file: %v", err)
	}
	if bf.Metadata.Tier != "repo" {
		t.Fatalf("Metadata.Tier = %q, want repo (test setup broken)", bf.Metadata.Tier)
	}
	bf.Metadata.Tier = "identity"
	tampered, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal tampered file: %v", err)
	}
	tamperedPath := dir + "/tampered.json"
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	// Import resolves its target table purely from the (now-lying) file
	// metadata, using the REAL per-tier table resolution — not a fake that
	// ignores what it's asked for.
	identityStore := newRealTierTable(t, client, "identity", "dev")
	openFn := func(tier, env string) (store.Store, string, error) {
		if tier != "identity" || env != "dev" {
			t.Fatalf("openFn called with tier=%q env=%q, want identity/dev (the tampered metadata)", tier, env)
		}
		return identityStore, "ffreis-vault-identity-dev", nil
	}
	if err := runBackupImport(ctx, tamperedPath, backup.ImportOptions{Overwrite: true}, noopLogger{}, openFn); err != nil {
		t.Fatalf("runBackupImport: %v (import itself must succeed — it never decrypts anything)", err)
	}

	var out bytes.Buffer
	err = runGet(ctx, identityStore, testSecretKey, "identity", "shared-key", "dev", true, &out)
	if err == nil {
		t.Fatal("runGet() against the transplanted item succeeded, want decrypt failure — the AAD tier binding did not survive a real store round-trip")
	}
	if strings.Contains(err.Error(), plaintext) || strings.Contains(out.String(), plaintext) {
		t.Fatalf("plaintext leaked despite the failed transplant decrypt: error=%q stdout=%q", err.Error(), out.String())
	}
}

// TestIntegrationTierBoundary_PutUnderOneTierAbsentFromOthers proves the
// tier/table separation itself against REAL DynamoDB Local, using the exact
// per-tier table names vaulttier.TableName resolves (not one throwaway
// table standing in for all three, as every other integration test uses): a
// secret put under the "repo" tier's real table must be genuinely absent
// from the real "identity" and "root" tables for the same env/key, not just
// present in "repo".
func TestIntegrationTierBoundary_PutUnderOneTierAbsentFromOthers(t *testing.T) {
	client := newIntegrationClient(t)
	repoStore := newRealTierTable(t, client, "repo", "dev")
	identityStore := newRealTierTable(t, client, "identity", "dev")
	rootStore := newRealTierTable(t, client, "root", "dev")
	ctx := context.Background()

	const key = "tier-boundary-key"
	if err := runPut(ctx, repoStore, noopLogger{}, testSecretKey, "repo", key, "dev", "tester",
		strings.NewReader("only-in-repo-tier")); err != nil {
		t.Fatalf("seed runPut under repo tier: %v", err)
	}

	if _, err := repoStore.Get(ctx, vaultProject, "dev", store.ItemTypeSecret, key); err != nil {
		t.Fatalf("Get against repo's own table: %v, want the item to be present", err)
	}

	for tier, st := range map[string]store.Store{"identity": identityStore, "root": rootStore} {
		if _, err := st.Get(ctx, vaultProject, "dev", store.ItemTypeSecret, key); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(%q) against the %s tier's own (different, real) table = %v, want store.ErrNotFound — "+
				"a repo-tier secret must never be reachable from another tier's table", key, tier, err)
		}
	}
}
