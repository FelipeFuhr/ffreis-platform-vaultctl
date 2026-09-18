package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func sourceAndPrintVar(path, varName string) (string, error) {
	c := exec.CommandContext(context.Background(), "sh", "-c", fmt.Sprintf(`. "$1" && printf '%%s' "$%s"`, varName), "sh", path)
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("run: %w", err)
	}
	return string(out), nil
}

func exportEnvDeps(plaintext string) store.Store {
	item := encryptedVaultItem("identity", "dev", "api_key", plaintext)
	return fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}
}

func TestRunExportEnv_WritesShellQuotedFileMode0600(t *testing.T) {
	st := exportEnvDeps("value with 'quotes' inside")

	var writtenPath string
	var writtenData []byte
	var writtenMode os.FileMode
	writeFile := func(path string, data []byte, mode os.FileMode) error {
		writtenPath, writtenData, writtenMode = path, data, mode
		return nil
	}
	var chmodPath string
	var chmodMode os.FileMode
	var chmodCalls int
	chmod := func(path string, mode os.FileMode) error {
		chmodPath, chmodMode = path, mode
		chmodCalls++
		return nil
	}

	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev",
		"SECRET_VALUE", "/tmp/out.env", writeFile, chmod, &stdout)
	if err != nil {
		t.Fatalf("runExportEnv() error = %v", err)
	}

	if writtenPath != "/tmp/out.env" {
		t.Fatalf("writeFile path = %q, want /tmp/out.env", writtenPath)
	}
	if writtenMode != 0o600 {
		t.Fatalf("writeFile mode = %o, want 0600", writtenMode)
	}
	// runExportEnv must explicitly chmod the file it just wrote, not rely on
	// writeFile's mode argument alone — see writeSecretFile's doc for why
	// (os.WriteFile never corrects an existing file's permissions).
	if chmodCalls != 1 {
		t.Fatalf("chmod called %d times, want exactly 1", chmodCalls)
	}
	if chmodPath != "/tmp/out.env" || chmodMode != 0o600 {
		t.Fatalf("chmod(%q, %o), want (/tmp/out.env, 0600)", chmodPath, chmodMode)
	}
	wantLine := `export SECRET_VALUE='value with '\''quotes'\'' inside'` + "\n"
	if string(writtenData) != wantLine {
		t.Fatalf("writeFile data = %q, want %q", writtenData, wantLine)
	}
	if bytes.Contains(stdout.Bytes(), []byte("value with")) {
		t.Fatalf("plaintext leaked to vaultctl's own stdout: %q", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("/tmp/out.env")) {
		t.Fatalf("stdout should confirm the path it wrote, got: %q", stdout.String())
	}
}

func TestRunExportEnv_ShellQuotedValueSourcesCleanly(t *testing.T) {
	const value = `tricky$val'ue "with" $(command) substitution`
	st := exportEnvDeps(value)

	dir := t.TempDir()
	path := dir + "/out.env"

	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev",
		"ROUNDTRIP_VALUE", path, os.WriteFile, os.Chmod, &stdout)
	if err != nil {
		t.Fatalf("runExportEnv() error = %v", err)
	}

	got, err := sourceAndPrintVar(path, "ROUNDTRIP_VALUE")
	if err != nil {
		t.Fatalf("source+print failed: %v", err)
	}
	if got != value {
		t.Fatalf("round-tripped value = %q, want %q", got, value)
	}
}

// TestRunExportEnv_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase
// is export-env's analogue of exec's identically-purposed test: a wrong
// VAULTCTL_SECRET_KEY must fail decryption without the FULL error string
// (not just its type) ever containing the plaintext or either passphrase,
// and without writing anything to the file or to vaultctl's own stdout.
func TestRunExportEnv_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-export-env-must-never-leak-in-error-text"
	const wrongKey = "98765432109876543210987654321098"
	st := exportEnvDeps(plaintext)

	var writeFileCalled bool
	writeFile := func(string, []byte, os.FileMode) error {
		writeFileCalled = true
		return nil
	}

	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, wrongKey, "identity", "api_key", "dev",
		"X", "/tmp/out.env", writeFile, noopChmod, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want decrypt failure under a wrong passphrase")
	}

	full := err.Error()
	for _, sensitive := range []string{plaintext, testSecretKey, wrongKey} {
		if strings.Contains(full, sensitive) {
			t.Fatalf("decrypt-failure error text leaked a sensitive value %q: %q", sensitive, full)
		}
	}
	if writeFileCalled {
		t.Fatal("writeFile must not be called when decryption fails")
	}
	if stdout.Len() != 0 {
		t.Fatalf("vaultctl's own stdout must stay empty on decrypt failure, got: %q", stdout.String())
	}
}

// TestRunExportEnv_CorruptedCiphertextDecryptFailureNeverLeaksPlaintext is
// the corrupted-ciphertext analogue — authentication failure rather than a
// key mismatch, which must be equally safe.
func TestRunExportEnv_CorruptedCiphertextDecryptFailureNeverLeaksPlaintext(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-export-env-corrupted-ciphertext"
	item := encryptedVaultItem("identity", "dev", "api_key", plaintext)
	corrupted := *item
	corrupted.Value = corrupted.Value[:len(corrupted.Value)-4] + "AAAA"
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return &corrupted, nil
	}}

	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev",
		"X", "/tmp/out.env", func(string, []byte, os.FileMode) error { return nil }, noopChmod, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want decrypt failure for corrupted ciphertext")
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatalf("corrupted-ciphertext error text leaked the plaintext: %q", err.Error())
	}
}

// TestRunExportEnv_CorrectsPreExistingLoosePermissions proves export-env
// does not silently inherit a pre-existing file's looser mode. os.WriteFile
// documents that its mode argument only applies when CREATING a file — "if
// the file does not exist, WriteFile creates it with permissions perm...
// otherwise WriteFile truncates it before writing, without changing
// permissions." A stale file at --out left over at 0644 (world-readable)
// from an earlier run, a different umask, or some other tool would
// otherwise silently keep receiving fresh secret plaintext at 0644 while
// vaultctl's own confirmation message keeps claiming "mode 0600" — exactly
// the kind of leak this vault exists to prevent. This test uses the REAL
// os.WriteFile and os.Chmod (not fakes) against a real pre-existing file, so
// it only passes if runExportEnv's own logic (not the test double) performs
// the correction.
func TestRunExportEnv_CorrectsPreExistingLoosePermissions(t *testing.T) {
	st := exportEnvDeps("value-for-permission-test")

	dir := t.TempDir()
	path := dir + "/out.env"
	// Simulate a stale, world-readable file already sitting at this path.
	if err := os.WriteFile(path, []byte("stale contents"), 0o644); err != nil {
		t.Fatalf("seed pre-existing file: %v", err)
	}
	preInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat seeded file: %v", err)
	}
	if preInfo.Mode().Perm() != 0o644 {
		t.Fatalf("seeded file mode = %o, want 0644 (test setup broken)", preInfo.Mode().Perm())
	}

	var stdout bytes.Buffer
	err = runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev",
		"SECRET_VALUE", path, os.WriteFile, os.Chmod, &stdout)
	if err != nil {
		t.Fatalf("runExportEnv() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("exported file mode = %o, want 0600 — a pre-existing looser mode must be corrected, not inherited", info.Mode().Perm())
	}
}

func TestRunExportEnv_MissingOutIsError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X", "",
		func(string, []byte, os.FileMode) error { return nil }, noopChmod, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want error for missing --out")
	}
}

func TestRunExportEnv_MissingAsIsError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return nil }, noopChmod, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want error for missing --as")
	}
}

func TestRunExportEnv_WriteFileErrorPropagates(t *testing.T) {
	st := exportEnvDeps("value")
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return errTest("disk full") }, noopChmod, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want error propagated from writeFile")
	}
}

func TestNewExportEnvCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newExportEnvCmd(&deps{})
	if !strings.HasPrefix(cmd.Use, "export-env <tier> <key>") {
		t.Errorf("Use = %q, want prefix %q", cmd.Use, "export-env <tier> <key>")
	}
	for _, name := range []string{"env", "as", "out"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if !strings.Contains(cmd.Long, "shred") {
		t.Error("long help does not document the caller's responsibility to shred the file")
	}
}

func TestShellQuoteSingle(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"simple": `'simple'`,
		"":       `''`,
		"it's":   `'it'\''s'`,
	}
	for in, want := range cases {
		if got := shellQuoteSingle(in); got != want {
			t.Errorf("shellQuoteSingle(%q) = %q, want %q", in, got, want)
		}
	}
}
