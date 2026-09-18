package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newExportEnvCmd(d *deps) *cobra.Command {
	var env, as, out string

	cmd := &cobra.Command{
		Use:   "export-env <tier> <key> --as NAME --out <path> --env <dev|prod>",
		Short: "Write a shell-sourceable export of a decrypted secret to a file",
		Long: `export-env decrypts <tier>/<key> and writes a single line,
export NAME=<value> (shell-quoted), to the file named by the required --out
flag.

There is no default output location: writing to stdout or an implicit path
would risk exactly the transcript leak this vault is meant to prevent, so
the caller must say exactly where the value goes. --as (the env var name) is
required for the same reason --as is required on 'exec' — no silent default
such as uppercasing the key, since that could collide or surprise.

The file is written with mode 0600. vaultctl itself prints nothing but a
confirmation of the path it wrote — never the value — to stdout.

The caller is responsible for shredding the file once it is no longer
needed (e.g. 'shred -u <path>' or 'rm -P <path>') — vaultctl does not do
this for you, since it has no way to know when the caller is done with it.

Example:
  vaultctl export-env identity github-pat --as GITHUB_TOKEN --env prod \
    --out /tmp/github-pat.env
  source /tmp/github-pat.env && shred -u /tmp/github-pat.env`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, key := args[0], args[1]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runExportEnv(cmd.Context(), st, d.log, d.secretKey, tier, key, env, as, out, os.WriteFile, os.Chmod, cmd.OutOrStdout())
		},
	}

	addEnvFlag(cmd, &env)
	cmd.Flags().StringVar(&as, flagAs, "", "Environment variable name to export the decrypted value as (required)")
	cmd.Flags().StringVar(&out, flagOut, "", "File path to write the export line to, mode 0600 (required, no default)")
	_ = cmd.MarkFlagRequired(flagAs)
	_ = cmd.MarkFlagRequired(flagOut)
	return cmd
}

func runExportEnv(
	ctx context.Context,
	st store.Store,
	log logger.Logger,
	secretKey, tier, key, env, as, out string,
	writeFile func(string, []byte, os.FileMode) error,
	chmod func(string, os.FileMode) error,
	stdout io.Writer,
) error {
	if as == "" {
		return errors.New("--as is required: the environment variable name to export the decrypted value as")
	}
	if out == "" {
		return errors.New("--out is required: export-env never defaults to stdout or an implicit location")
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

	line := "export " + as + "=" + shellQuoteSingle(string(plaintext)) + "\n"
	if err := writeSecretFile(writeFile, chmod, out, []byte(line), 0o600); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}

	// Never log or print the value — only tier/key name, target env var
	// name, and destination path.
	if log != nil {
		log.Info("secret exported to file",
			zap.String("tier", tier),
			zap.String("key", key),
			zap.String(flagAs, as),
			zap.String("path", out),
		)
	}

	_, err = fmt.Fprintf(stdout, "wrote %s (mode 0600) — remember to shred it once you're done, e.g.: shred -u %s\n", out, out)
	return err
}

// shellQuoteSingle wraps s in single quotes for safe use in a POSIX shell
// 'export NAME=...' line, escaping any embedded single quote.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
