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

	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev",
		"SECRET_VALUE", "/tmp/out.env", writeFile, &stdout)
	if err != nil {
		t.Fatalf("runExportEnv() error = %v", err)
	}

	if writtenPath != "/tmp/out.env" {
		t.Fatalf("writeFile path = %q, want /tmp/out.env", writtenPath)
	}
	if writtenMode != 0o600 {
		t.Fatalf("writeFile mode = %o, want 0600", writtenMode)
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
		"ROUNDTRIP_VALUE", path, os.WriteFile, &stdout)
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

func TestRunExportEnv_MissingOutIsError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X", "",
		func(string, []byte, os.FileMode) error { return nil }, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want error for missing --out")
	}
}

func TestRunExportEnv_MissingAsIsError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return nil }, &stdout)
	if err == nil {
		t.Fatal("runExportEnv() error = nil, want error for missing --as")
	}
}

func TestRunExportEnv_WriteFileErrorPropagates(t *testing.T) {
	st := exportEnvDeps("value")
	var stdout bytes.Buffer
	err := runExportEnv(context.Background(), st, noopLogger{}, testSecretKey, "identity", "api_key", "dev", "X", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return errTest("disk full") }, &stdout)
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
