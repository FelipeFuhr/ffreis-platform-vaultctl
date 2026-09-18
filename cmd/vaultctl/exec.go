package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newExecCmd(d *deps) *cobra.Command {
	var env, as string

	cmd := &cobra.Command{
		Use:   "exec <tier> <key> --as NAME --env <dev|prod> -- <cmd> [args...]",
		Short: "Decrypt a secret in-process and run a child command with it injected into the environment",
		Long: `exec decrypts <tier>/<key> and runs the command after "--" with the
plaintext injected into the child process's environment as NAME=<value>
(NAME set via the required --as flag — there is no default, since guessing
one, e.g. by uppercasing the key, risks a silent collision or surprise).

The plaintext is never written to vaultctl's own stdout or stderr, never
logged (not even at debug level), and never appears in an error message — it
exists only in this process's memory and in the child process's environment
block.

The child's own stdin/stdout/stderr are connected directly to this process's
— vaultctl does not buffer or inspect them — and its exit code is propagated
as this command's exit code.

Example:
  vaultctl exec identity github-pat --as GITHUB_TOKEN --env prod -- ./deploy.sh`,
		Args: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash != 2 {
				return errors.New("usage: exec <tier> <key> --as NAME -- <cmd> [args...] (exactly tier and key before --)")
			}
			if len(args) <= dash {
				return errors.New("missing command after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			tier, key := args[0], args[1]
			childArgs := args[dash:]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runExec(cmd.Context(), st, d.log, d.secretKey, tier, key, env, as, childArgs,
				cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	addEnvFlag(cmd, &env)
	cmd.Flags().StringVar(&as, flagAs, "", "Environment variable name to inject the decrypted value as (required)")
	_ = cmd.MarkFlagRequired(flagAs)
	return cmd
}

func runExec(
	ctx context.Context,
	st store.Store,
	log logger.Logger,
	secretKey, tier, key, env, as string,
	childArgs []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	if as == "" {
		return errors.New("--as is required: the environment variable name to inject the decrypted value as")
	}
	if err := requireSecretKey(secretKey); err != nil {
		return err
	}

	item, err := getVaultItem(ctx, st, env, key)
	if err != nil {
		return err
	}
	plaintext, err := decryptVaultItem(secretKey, tier, env, item)
	if err != nil {
		return err
	}

	// Never log the value itself — tier/key name and target env var name only.
	if log != nil {
		log.Debug("running child process with secret injected into its environment",
			zap.String("tier", tier),
			zap.String("key", key),
			zap.String(flagAs, as),
		)
	}

	return runChildWithSecretEnv(ctx, as, plaintext, childArgs, stdin, stdout, stderr)
}

// runChildWithSecretEnv runs childArgs[0] with childArgs[1:] as its
// arguments, injecting as=plaintext into its environment. The child's own
// stdin/stdout/stderr are wired directly to the given streams — vaultctl
// never reads, buffers, or logs anything the child writes.
func runChildWithSecretEnv(
	ctx context.Context,
	as string,
	plaintext []byte,
	childArgs []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	// #nosec G204 -- childArgs[0] is the operator-supplied command after "--",
	// exactly as a shell would run it; this is the documented purpose of exec.
	c := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...)
	c.Env = append(os.Environ(), as+"="+string(plaintext))
	c.Stdin = stdin
	c.Stdout = stdout
	c.Stderr = stderr

	err := c.Run()
	if err == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return &ExitError{Code: exitErr.ExitCode()}
	}
	// Any other failure (e.g. command not found) comes from exec.Error /
	// os.PathError, whose text is only ever the command name — never env
	// values — so it is safe to wrap and surface directly.
	return fmt.Errorf("run child command %q: %w", childArgs[0], err)
}
