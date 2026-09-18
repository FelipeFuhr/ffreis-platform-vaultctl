package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func execDeps(plaintext string) store.Store {
	item := encryptedVaultItem("identity", "dev", "api_key", plaintext)
	return fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return item, nil
	}}
}

// TestRunExec_InjectsPlaintextIntoChildEnv proves the value reaches the
// child process only via its environment — nothing about it touches
// vaultctl's own stdout/stderr.
func TestRunExec_InjectsPlaintextIntoChildEnv(t *testing.T) {
	st := execDeps("s3cr3t-child-value")

	outFile := filepath.Join(t.TempDir(), "captured.txt")
	t.Setenv("VAULTCTL_EXEC_TEST_OUT_FILE", outFile)

	var stdout, stderr bytes.Buffer
	err := runExec(
		context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "SECRET_VALUE",
		[]string{"sh", "-c", `printf '%s' "$SECRET_VALUE" > "$VAULTCTL_EXEC_TEST_OUT_FILE"`},
		strings.NewReader(""), &stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("runExec() error = %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(got) != "s3cr3t-child-value" {
		t.Fatalf("child received %q via env, want %q", got, "s3cr3t-child-value")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("vaultctl's own streams must stay empty: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunExec_PropagatesChildExitCode(t *testing.T) {
	st := execDeps("value")

	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X",
		[]string{"sh", "-c", "exit 7"}, strings.NewReader(""), &stdout, &stderr)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("runExec() error = %v (%T), want *ExitError", err, err)
	}
	if exitErr.Code != 7 {
		t.Fatalf("ExitError.Code = %d, want 7", exitErr.Code)
	}
}

func TestRunExec_MissingAsIsError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runExec() error = nil, want error for missing --as")
	}
}

func TestRunExec_MissingSecretKey(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, "", "identity", "api_key", "dev", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runExec() error = nil, want error for missing secret key")
	}
}

func TestRunExec_SecretNotFound(t *testing.T) {
	t.Parallel()

	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return nil, store.ErrNotFound
	}}
	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, testSecretKey, "identity", "missing", "dev", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != exitNotFound {
		t.Fatalf("runExec() error = %v, want *ExitError{Code: exitNotFound}", err)
	}
}

func TestRunExec_CommandNotFoundErrorNeverIncludesValue(t *testing.T) {
	st := execDeps("value-that-must-not-leak")
	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X",
		[]string{"vaultctl-test-definitely-not-a-real-binary-xyz"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runExec() error = nil, want error for missing binary")
	}
	if strings.Contains(err.Error(), "value-that-must-not-leak") {
		t.Fatalf("error message leaked the plaintext: %v", err)
	}
}

// TestRunExec_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase
// deliberately triggers a decrypt failure (wrong VAULTCTL_SECRET_KEY) and
// inspects the FULL error string vaultctl returns — not just its type — to
// prove that neither the plaintext nor either passphrase (right or wrong)
// ever rides along in the error text that ultimately reaches stderr.
func TestRunExec_WrongPassphraseDecryptFailureNeverLeaksPlaintextOrPassphrase(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-must-never-leak-in-error-text"
	const wrongKey = "98765432109876543210987654321098"
	st := execDeps(plaintext)

	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, wrongKey, "identity", "api_key", "dev", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runExec() error = nil, want decrypt failure under a wrong passphrase")
	}

	full := err.Error()
	for _, sensitive := range []string{plaintext, testSecretKey, wrongKey} {
		if strings.Contains(full, sensitive) {
			t.Fatalf("decrypt-failure error text leaked a sensitive value %q: %q", sensitive, full)
		}
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("vaultctl's own streams must stay empty on decrypt failure: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestRunExec_CorruptedCiphertextDecryptFailureNeverLeaksPlaintext is the
// corrupted-ciphertext analogue of the wrong-passphrase test above — a
// distinct failure mode (authentication failure / malformed encoding rather
// than a key mismatch) that must be equally safe.
func TestRunExec_CorruptedCiphertextDecryptFailureNeverLeaksPlaintext(t *testing.T) {
	t.Parallel()

	const plaintext = "s3cr3t-corrupted-ciphertext-must-not-leak"
	item := encryptedVaultItem("identity", "dev", "api_key", plaintext)
	corrupted := *item
	corrupted.Value = corrupted.Value[:len(corrupted.Value)-4] + "AAAA"
	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return &corrupted, nil
	}}

	var stdout, stderr bytes.Buffer
	err := runExec(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runExec() error = nil, want decrypt failure for corrupted ciphertext")
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatalf("corrupted-ciphertext error text leaked the plaintext: %q", err.Error())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("vaultctl's own streams must stay empty on decrypt failure: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestNewExecCmd_EndToEnd_SplitsTierKeyAndCommandAtDash exercises the real
// cobra flag-parsing path, proving the "-- " splitting works against real
// pflag parsing with TWO positional args (tier, key) before the dash.
func TestNewExecCmd_EndToEnd_SplitsTierKeyAndCommandAtDash(t *testing.T) {
	t.Parallel()

	cmd := newExecCmd(&deps{})
	if err := cmd.Args(cmd, []string{"identity", "api_key"}); err == nil {
		t.Error("Args() with no -- separator should error")
	}
}

func TestNewExecCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newExecCmd(&deps{})
	if !strings.HasPrefix(cmd.Use, "exec <tier> <key>") {
		t.Errorf("Use = %q, want prefix %q", cmd.Use, "exec <tier> <key>")
	}
	for _, name := range []string{"env", "as"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
}
