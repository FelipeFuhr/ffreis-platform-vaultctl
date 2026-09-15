package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

func TestMainProcess(t *testing.T) {
	if os.Getenv("RUN_VAULTCTL_MAIN_TEST") == "1" {
		switch {
		case os.Getenv("GO_WANT_HELP") == "1":
			os.Args = []string{"vaultctl", "--help"}
		case os.Getenv("GO_WANT_BAD_FLAG") == "1":
			os.Args = []string{"vaultctl", "--bad-flag"}
		}
		main()
		return
	}

	t.Run("success exits zero", func(t *testing.T) {
		cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestMainProcess")
		cmd.Env = append(os.Environ(), "RUN_VAULTCTL_MAIN_TEST=1", "GO_WANT_HELP=1")
		if err := cmd.Run(); err != nil {
			t.Fatalf("main() subprocess failed: %v", err)
		}
	})

	t.Run("error exits one", func(t *testing.T) {
		cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestMainProcess")
		cmd.Env = append(os.Environ(), "RUN_VAULTCTL_MAIN_TEST=1", "GO_WANT_BAD_FLAG=1")
		err := cmd.Run()
		if err == nil {
			t.Fatal("expected non-zero exit")
		}
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 1 {
			t.Fatalf("unexpected exit error: %v", err)
		}
	})
}
