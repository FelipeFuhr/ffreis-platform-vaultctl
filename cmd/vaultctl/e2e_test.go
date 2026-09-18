//go:build e2e

// True black-box E2E coverage: these tests `go build` the ACTUAL vaultctl
// binary and exec it as a real OS subprocess — never an in-process cobra
// call — against a real DynamoDB Local, matching the rigor
// platform-configctl applied to its own 'secret exec' (see cmd/secret_exec_test.go
// on that binary): capture real stdout/stderr and assert no plaintext ever
// appears in them.
//
// The real binary has no --table/--endpoint override (by design — see
// internal/vaulttier), so these tests redirect it at DynamoDB Local the same
// way an operator would redirect the AWS SDK anywhere else: the standard
// AWS_ENDPOINT_URL environment variable, which aws-sdk-go-v2's default
// config loader honours automatically.
//
// Run with: make test-e2e (starts DynamoDB Local via podman, same as
// test-integration). Skipped entirely when no endpoint is reachable.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	e2eSecretKey   = "e2e0123456789012345678901234567"
	e2eLocalAccess = "local"
	e2eLocalRegion = "us-east-1"
	e2eTable       = "ffreis-vault-identity-dev"
)

func e2eDDBEndpoint() string {
	if v := os.Getenv("DYNAMODB_ENDPOINT"); v != "" {
		return v
	}
	return "http://localhost:8000"
}

func requireDDBLocal(t *testing.T) string {
	t.Helper()
	endpoint := e2eDDBEndpoint()
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", host)
	if err != nil {
		t.Skipf("DynamoDB Local not reachable at %s (%v) — run `make test-e2e`", endpoint, err)
	}
	_ = conn.Close()
	return endpoint
}

func e2eDDBClient(endpoint string) *dynamodb.Client {
	return dynamodb.New(dynamodb.Options{
		Region:       e2eLocalRegion,
		BaseEndpoint: awssdk.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider(e2eLocalAccess, e2eLocalAccess, ""),
	})
}

// ensureE2ETable idempotently creates the real ffreis-vault-identity-dev
// table shape against DynamoDB Local — the real binary has no --table
// override, so an E2E test necessarily uses the real table name it would
// resolve internally (harmless here since this is an ephemeral local
// instance, never real AWS).
func ensureE2ETable(t *testing.T, endpoint string) {
	t.Helper()
	client := e2eDDBClient(endpoint)
	ctx := context.Background()
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: awssdk.String(e2eTable),
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
		t.Fatalf("CreateTable(%s): %v", e2eTable, err)
	}
}

func deleteE2EItem(t *testing.T, endpoint, key string) {
	t.Helper()
	client := e2eDDBClient(endpoint)
	_, _ = client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: awssdk.String(e2eTable),
		Key: map[string]ddbtypes.AttributeValue{
			"PK": &ddbtypes.AttributeValueMemberS{Value: "PROJECT#vault#ENV#dev"},
			"SK": &ddbtypes.AttributeValueMemberS{Value: "SECRET#" + key},
		},
	})
}

var (
	vaultctlBinOnce sync.Once
	vaultctlBinPath string
	vaultctlBinErr  error
)

// buildVaultctlBinary compiles the REAL vaultctl binary once per test
// process (via `go build`, a real external command — this is deliberately
// not `go test`'s own re-exec trick) and returns its path.
func buildVaultctlBinary(t *testing.T) string {
	t.Helper()
	vaultctlBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vaultctl-e2e-bin")
		if err != nil {
			vaultctlBinErr = fmt.Errorf("MkdirTemp: %w", err)
			return
		}
		path := filepath.Join(dir, "vaultctl")
		cmd := exec.Command("go", "build", "-o", path, ".")
		out, err := cmd.CombinedOutput()
		if err != nil {
			vaultctlBinErr = fmt.Errorf("go build vaultctl: %w\n%s", err, out)
			return
		}
		vaultctlBinPath = path
	})
	if vaultctlBinErr != nil {
		t.Fatalf("building the real vaultctl binary: %v", vaultctlBinErr)
	}
	return vaultctlBinPath
}

// vaultctlCmd builds an *exec.Cmd for a real vaultctl subprocess, wired at
// endpoint via the standard AWS_ENDPOINT_URL, with VAULTCTL_SECRET_KEY set —
// but deliberately WITHOUT VAULTCTL_NO_REVEAL unless extraEnv sets it, and
// stdin/stdout/stderr fully under the test's control (never the test
// process's own terminal).
func vaultctlCmd(t *testing.T, binPath, endpoint string, extraEnv []string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append([]string{
		"AWS_ENDPOINT_URL=" + endpoint,
		"AWS_ACCESS_KEY_ID=" + e2eLocalAccess,
		"AWS_SECRET_ACCESS_KEY=" + e2eLocalAccess,
		"AWS_DEFAULT_REGION=" + e2eLocalRegion,
		"VAULTCTL_SECRET_KEY=" + e2eSecretKey,
		"PATH=" + os.Getenv("PATH"),
	}, extraEnv...)
	return cmd
}

func e2ePut(t *testing.T, binPath, endpoint, key, value string) {
	t.Helper()
	cmd := vaultctlCmd(t, binPath, endpoint, nil, "put", "identity", key, "--env", "dev")
	cmd.Stdin = strings.NewReader(value)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("real `vaultctl put` subprocess failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
}

// TestE2E_Exec_InjectsSecretIntoChildEnvNeverIntoVaultctlsOwnStreams runs the
// REAL vaultctl binary as a subprocess doing `exec`, which itself spawns a
// grandchild that dumps the injected env var to its own stdout (captured by
// THIS test, standing in for a real terminal). vaultctl's own captured
// stdout/stderr must stay completely empty.
func TestE2E_Exec_InjectsSecretIntoChildEnvNeverIntoVaultctlsOwnStreams(t *testing.T) {
	endpoint := requireDDBLocal(t)
	ensureE2ETable(t, endpoint)
	binPath := buildVaultctlBinary(t)

	key := fmt.Sprintf("e2e-exec-%d", time.Now().UnixNano())
	const plaintext = "s3cr3t-e2e-exec-value"
	e2ePut(t, binPath, endpoint, key, plaintext)
	t.Cleanup(func() { deleteE2EItem(t, endpoint, key) })

	cmd := vaultctlCmd(t, binPath, endpoint, nil,
		"exec", "identity", key, "--as", "INJECTED_SECRET", "--env", "dev",
		"--", "sh", "-c", `printf '%s' "$INJECTED_SECRET"`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("real `vaultctl exec` subprocess failed: %v\nstderr=%s", err, stderr.String())
	}
	// The GRANDCHILD's stdout is what this test captured (vaultctl wires it
	// straight through) — it must contain the plaintext, proving the value
	// really flowed through the injected env var.
	if stdout.String() != plaintext {
		t.Fatalf("captured stdout = %q, want the injected plaintext %q", stdout.String(), plaintext)
	}
	if stderr.Len() != 0 {
		t.Fatalf("vaultctl's own stderr must stay empty, got: %q", stderr.String())
	}
}

// TestE2E_ExportEnv_WritesFileNeverStdout runs the real binary's
// `export-env` and confirms the plaintext lands ONLY in the file it wrote,
// never in vaultctl's own captured stdout/stderr.
func TestE2E_ExportEnv_WritesFileNeverStdout(t *testing.T) {
	endpoint := requireDDBLocal(t)
	ensureE2ETable(t, endpoint)
	binPath := buildVaultctlBinary(t)

	key := fmt.Sprintf("e2e-exportenv-%d", time.Now().UnixNano())
	const plaintext = "s3cr3t-e2e-exportenv-value"
	e2ePut(t, binPath, endpoint, key, plaintext)
	t.Cleanup(func() { deleteE2EItem(t, endpoint, key) })

	outPath := filepath.Join(t.TempDir(), "out.env")
	cmd := vaultctlCmd(t, binPath, endpoint, nil,
		"export-env", "identity", key, "--as", "EXPORTED_SECRET", "--out", outPath, "--env", "dev")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("real `vaultctl export-env` subprocess failed: %v\nstderr=%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), plaintext) || strings.Contains(stderr.String(), plaintext) {
		t.Fatalf("plaintext leaked to vaultctl's own captured streams: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if !strings.Contains(string(written), plaintext) {
		t.Fatalf("exported file missing the plaintext, got: %s", written)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("exported file mode = %o, want 0600", info.Mode().Perm())
	}
}

// TestE2E_Get_RevealRefusedUnderNoRevealKillSwitch runs the real binary's
// `get --reveal` with VAULTCTL_NO_REVEAL set and confirms it refuses,
// capturing real stdout/stderr and asserting the plaintext never appears in
// either.
func TestE2E_Get_RevealRefusedUnderNoRevealKillSwitch(t *testing.T) {
	endpoint := requireDDBLocal(t)
	ensureE2ETable(t, endpoint)
	binPath := buildVaultctlBinary(t)

	key := fmt.Sprintf("e2e-noreveal-%d", time.Now().UnixNano())
	const plaintext = "s3cr3t-must-never-appear"
	e2ePut(t, binPath, endpoint, key, plaintext)
	t.Cleanup(func() { deleteE2EItem(t, endpoint, key) })

	cmd := vaultctlCmd(t, binPath, endpoint, []string{"VAULTCTL_NO_REVEAL=1"},
		"get", "identity", key, "--env", "dev", "--reveal")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("real `vaultctl get --reveal` subprocess succeeded, want a non-zero exit under VAULTCTL_NO_REVEAL=1")
	}
	if strings.Contains(stdout.String(), plaintext) || strings.Contains(stderr.String(), plaintext) {
		t.Fatalf("plaintext leaked despite the kill switch: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "VAULTCTL_NO_REVEAL") {
		t.Errorf("stderr should name VAULTCTL_NO_REVEAL as the reason, got: %q", stderr.String())
	}
}

// TestE2E_Get_MaskedByDefaultShowsFingerprintNotValue is the baseline
// black-box proof for plain `get` (no --reveal): the real binary's captured
// stdout shows the fingerprint and masked value, never the plaintext.
func TestE2E_Get_MaskedByDefaultShowsFingerprintNotValue(t *testing.T) {
	endpoint := requireDDBLocal(t)
	ensureE2ETable(t, endpoint)
	binPath := buildVaultctlBinary(t)

	key := fmt.Sprintf("e2e-masked-%d", time.Now().UnixNano())
	const plaintext = "s3cr3t-masked-value"
	e2ePut(t, binPath, endpoint, key, plaintext)
	t.Cleanup(func() { deleteE2EItem(t, endpoint, key) })

	cmd := vaultctlCmd(t, binPath, endpoint, nil, "get", "identity", key, "--env", "dev")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("real `vaultctl get` subprocess failed: %v\nstderr=%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), plaintext) {
		t.Fatalf("plaintext leaked to captured stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "value:       ***") {
		t.Errorf("captured stdout should mask the value, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "fingerprint:") {
		t.Errorf("captured stdout should include a fingerprint line, got: %q", stdout.String())
	}
}
