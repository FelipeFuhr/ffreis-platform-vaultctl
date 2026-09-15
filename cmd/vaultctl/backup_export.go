package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newBackupExportCmd(d *deps) *cobra.Command {
	var tier, env, output string
	var includeSecrets bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a vault tier (and optionally secret ciphertext) to a JSON backup file",
		Long: `export reads every item in <tier>'s table for --env and writes it to
a JSON backup file, reusing platform-configctl's internal/backup format and
checksum unchanged.

This backs the vault's own recovery story: PITR on the root table plus a
'backup export' of root — which is ciphertext under the root key, and
therefore safe to store anywhere — is the vault's stated disaster-recovery
path. --include-secrets stores the already-encrypted ciphertext, never
plaintext; 'import' can only write it back as ciphertext too.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runBackupExport(cmd.Context(), st, d.log, d.secretKey, backupExportOpts{
				tier: tier, env: env, outputPath: output, includeSecrets: includeSecrets,
			}, os.WriteFile, callerIdentity(cmd.Context(), d), cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&tier, flagTier, "", "Vault tier: identity, repo, or root (required)")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (required)")
	cmd.Flags().BoolVar(&includeSecrets, "include-secrets", false, "Include secret ciphertext in the backup")
	_ = cmd.MarkFlagRequired(flagTier)
	_ = cmd.MarkFlagRequired("output")
	addEnvFlag(cmd, &env)
	return cmd
}

type backupExportOpts struct {
	tier           string
	env            string
	outputPath     string
	includeSecrets bool
}

func runBackupExport(
	ctx context.Context,
	st store.Store,
	log logger.Logger,
	secretKey string,
	opts backupExportOpts,
	writeFile func(string, []byte, os.FileMode) error,
	exportedBy string,
	stdout io.Writer,
) error {
	if opts.includeSecrets {
		if err := requireSecretKey(secretKey); err != nil {
			return err
		}
	}

	exporter := backup.NewExporter(st)
	bf, err := exporter.Export(ctx, vaultProject, opts.env, backup.ExportOptions{
		IncludeSecrets: opts.includeSecrets,
		ToolVersion:    resolvedVersion(),
		ExportedBy:     exportedBy,
	})
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	// Self-describes which table this came from, so 'backup import' — which
	// takes no --tier/--env — can resolve the same table on its own.
	bf.Metadata.Tier = opts.tier

	raw, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}

	if err := writeFile(opts.outputPath, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write file %s: %w", opts.outputPath, err)
	}

	if log != nil {
		log.Info("vault backup exported",
			zap.String("tier", opts.tier),
			zap.String("env", opts.env),
			zap.String("file", opts.outputPath),
			zap.Int("items", bf.Metadata.ItemCount),
		)
	}

	_, err = fmt.Fprintf(stdout, "exported %d item(s) from tier=%s env=%s to %s\n",
		bf.Metadata.ItemCount, opts.tier, opts.env, opts.outputPath)
	return err
}

func resolvedVersion() string {
	if version == "" {
		return "dev"
	}
	return version
}
