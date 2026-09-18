package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
)

var importResultStub = backup.ImportResult{Written: 1, Skipped: 0, Failed: 0}

// TestOpenStore_ValidatesTierEnvBeforeBuildingAnyClient proves openStore
// itself never dials AWS — it only validates tier/env and constructs a
// client from whatever aws.Config it's given, so an invalid tier/env is
// rejected without ever touching the network.
func TestOpenStore_ValidatesTierEnvBeforeBuildingAnyClient(t *testing.T) {
	t.Parallel()

	d := &deps{}
	if _, _, err := openStore(d, "not-a-tier", "dev"); err == nil {
		t.Error("openStore() error = nil, want error for an invalid tier")
	}
	if _, _, err := openStore(d, "identity", "not-an-env"); err == nil {
		t.Error("openStore() error = nil, want error for an invalid env")
	}

	st, table, err := openStore(d, "identity", "dev")
	if err != nil {
		t.Fatalf("openStore() error = %v, want nil for a valid tier/env", err)
	}
	if st == nil {
		t.Error("openStore() returned a nil Store for a valid tier/env")
	}
	if table != "ffreis-vault-identity-dev" {
		t.Errorf("openStore() table = %q, want ffreis-vault-identity-dev", table)
	}
}

func TestExitError_ErrorAndUnwrap(t *testing.T) {
	t.Parallel()

	inner := errors.New("boom")
	e := &ExitError{Code: 2, Err: inner}
	if e.Error() != "boom" {
		t.Errorf("Error() = %q, want boom", e.Error())
	}
	if !errors.Is(e.Unwrap(), inner) {
		t.Error("Unwrap() did not return the wrapped error")
	}

	var nilErr *ExitError
	if nilErr.Error() != "" {
		t.Errorf("nil ExitError.Error() = %q, want empty", nilErr.Error())
	}
	if nilErr.Unwrap() != nil {
		t.Error("nil ExitError.Unwrap() should return nil")
	}

	noInner := &ExitError{Code: 1}
	if noInner.Error() != "" {
		t.Errorf("ExitError with nil Err.Error() = %q, want empty", noInner.Error())
	}
}

func TestResolvedVersion(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = ""
	if got := resolvedVersion(); got != "dev" {
		t.Errorf("resolvedVersion() = %q, want dev when unset", got)
	}

	version = "v1.2.3"
	if got := resolvedVersion(); got != "v1.2.3" {
		t.Errorf("resolvedVersion() = %q, want v1.2.3", got)
	}
}

func TestReportImportResult(t *testing.T) {
	t.Parallel()

	if err := reportImportResult(nil, false, "table", &importResultStub); err != nil {
		t.Errorf("reportImportResult(nil log) error = %v, want nil (no-op)", err)
	}

	if err := reportImportResult(noopLogger{}, true, "table", &importResultStub); err != nil {
		t.Errorf("reportImportResult(dryRun) error = %v, want nil", err)
	}

	if err := reportImportResult(noopLogger{}, false, "table", &importResultStub); err != nil {
		t.Errorf("reportImportResult(success) error = %v, want nil", err)
	}
}

func TestReportImportResult_FailedItemsIsError(t *testing.T) {
	t.Parallel()

	failed := importResultStub
	failed.Failed = 2
	failed.Errors = []error{errors.New("item a"), errors.New("item b")}

	err := reportImportResult(noopLogger{}, false, "table", &failed)
	if err == nil {
		t.Fatal("reportImportResult() error = nil, want error when result.Failed > 0")
	}
}

// TestNewGetCmd_MissingSecretKeyFailsBeforeAnyNetworkCall exercises the real
// cobra Execute() path (not a direct function call) for a case guaranteed to
// return before openStore's Store is ever asked to do anything: a valid
// tier/env resolve a real (unconnected) DynamoDB client, then runGet's
// requireSecretKey check fails immediately, so this never dials AWS.
func TestNewGetCmd_MissingSecretKeyFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newGetCmd(&deps{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"identity", "k", "--env", "dev"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing VAULTCTL_SECRET_KEY")
	}
}

func TestNewPutCmd_MissingSecretKeyFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newPutCmd(&deps{})
	cmd.SetIn(bytes.NewReader(nil))
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"identity", "k", "--env", "dev"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing VAULTCTL_SECRET_KEY")
	}
}

func TestNewExecCmd_MissingSecretKeyFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newExecCmd(&deps{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"identity", "k", "--as", "X", "--env", "dev", "--", "true"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing VAULTCTL_SECRET_KEY")
	}
}

func TestNewExportEnvCmd_MissingSecretKeyFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newExportEnvCmd(&deps{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"identity", "k", "--as", "X", "--out", "/tmp/x.env", "--env", "dev"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing VAULTCTL_SECRET_KEY")
	}
}

func TestNewBackupImportCmd_MissingInputFailsBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	cmd := newBackupImportCmd(&deps{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing --input")
	}

	cmd2 := newBackupImportCmd(&deps{})
	cmd2.SetOut(&out)
	cmd2.SetErr(&errOut)
	cmd2.SetArgs([]string{"--input", "/definitely/does/not/exist.json"})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for a nonexistent --input file")
	}
}
