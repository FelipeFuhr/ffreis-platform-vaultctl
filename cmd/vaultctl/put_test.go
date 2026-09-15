package main

import (
	"context"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// TestVaultctlPut_RefusesEmptyValue is the named regression test for the
// empty-string incident: a real secret was once found live in a production
// table stored as SecretValue = "" — a write that succeeded and stored
// garbage, undetected because presence checks pass on an empty string. This
// proves vaultctl's `put` refuses that write outright rather than persisting
// it. Fails if the guard.ValidateSecretValue call in readVaultValueFromStdin
// is ever removed (proven by reverting it, confirming this test goes red,
// and reapplying it).
func TestVaultctlPut_RefusesEmptyValue(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "   ", "\t\n"} {
		st := fakeStore{}
		err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", strings.NewReader(raw))
		if err == nil {
			t.Fatalf("runPut(%q) error = nil, want error refusing an empty/whitespace-only value", raw)
		}
	}
}

// TestVaultctlPut_RefusesDashValue is the named regression test for the "-"
// incident: some CLI tools' "read from stdin" convention interprets a bare
// "-" argument as "read from stdin" and, used incorrectly, ends up storing
// the literal string "-" as the secret itself — succeeding while storing a
// placeholder byte instead of a real value.
func TestVaultctlPut_RefusesDashValue(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", strings.NewReader("-"))
	if err == nil {
		t.Fatal(`runPut("-") error = nil, want error refusing the literal string "-"`)
	}
}

func TestRunPut_CreatesNewItem(t *testing.T) {
	t.Parallel()

	var setItem *store.Item
	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, store.ErrNotFound
		},
		setFn: func(ctx context.Context, item *store.Item) error {
			setItem = item
			return nil
		},
	}

	err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "github-pat", "dev", "tester", strings.NewReader("ghp_abc"))
	if err != nil {
		t.Fatalf("runPut() error = %v", err)
	}
	if setItem == nil {
		t.Fatal("store.Set was not called")
	}
	if setItem.Version != 0 {
		t.Fatalf("Version = %d, want 0 for a new item", setItem.Version)
	}
	if setItem.Project != vaultProject {
		t.Fatalf("Project = %q, want %q", setItem.Project, vaultProject)
	}
	if setItem.Env != "dev" {
		t.Fatalf("Env = %q, want dev", setItem.Env)
	}
	if !setItem.Encrypted {
		t.Fatal("Encrypted = false, want true")
	}
	if setItem.Value == "ghp_abc" {
		t.Fatal("stored value must be ciphertext, not plaintext")
	}
	if setItem.UpdatedBy != "tester" {
		t.Fatalf("UpdatedBy = %q, want tester", setItem.UpdatedBy)
	}
}

func TestRunPut_CarriesExistingVersion(t *testing.T) {
	t.Parallel()

	var setItem *store.Item
	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return &store.Item{Version: 4}, nil
		},
		setFn: func(ctx context.Context, item *store.Item) error {
			setItem = item
			return nil
		},
	}

	if err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", strings.NewReader("new-value")); err != nil {
		t.Fatalf("runPut() error = %v", err)
	}
	if setItem.Version != 4 {
		t.Fatalf("Version = %d, want 4 (carried from existing)", setItem.Version)
	}
}

func TestRunPut_MissingSecretKey(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	if err := runPut(context.Background(), st, noopLogger{}, "", "identity", "k", "dev", "tester", strings.NewReader("v")); err == nil {
		t.Fatal("runPut() error = nil, want error for missing secret key")
	}
}

func TestRunPut_StdinReadError(t *testing.T) {
	t.Parallel()

	st := fakeStore{}
	if err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", errReader{}); err == nil {
		t.Fatal("runPut() error = nil, want error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errWriteFail }

var errWriteFail = errTest("pipe closed")

type errTest string

func (e errTest) Error() string { return string(e) }

func TestRunPut_StoreSetError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, store.ErrNotFound
		},
		setFn: func(context.Context, *store.Item) error {
			return errTest("write denied")
		},
	}
	if err := runPut(context.Background(), st, noopLogger{}, testSecretKey, "identity", "k", "dev", "tester", strings.NewReader("v")); err == nil {
		t.Fatal("runPut() error = nil, want error")
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"v\n":    "v",
		"v\r\n":  "v",
		"v":      "v",
		"v\n\n":  "v",
		"":       "",
		"\n":     "",
		"a\nb\n": "a\nb",
	}
	for in, want := range cases {
		if got := string(trimTrailingNewline([]byte(in))); got != want {
			t.Errorf("trimTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncryptVaultValue_EmptyKeyIsError(t *testing.T) {
	t.Parallel()

	if _, _, err := encryptVaultValue("", "identity", "dev", "k", []byte("v")); err == nil {
		t.Fatal("encryptVaultValue(\"\") error = nil, want error")
	}
}

func TestNewPutCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newPutCmd(&deps{})
	if cmd.Use != "put <tier> <key>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "put <tier> <key>")
	}
	if cmd.Flags().Lookup("env") == nil {
		t.Error("flag --env is not registered")
	}
	if !strings.Contains(cmd.Long, "stdin") {
		t.Error("long help does not mention stdin")
	}
}
