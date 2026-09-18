package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newBackupImportCmd(d *deps) *cobra.Command {
	var input string
	var dryRun, overwrite bool

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Load a vault backup file into DynamoDB",
		Long: `Writes a backup file's contents back to DynamoDB.

No --tier/--env flags here (platform-configctl's own loader takes none
either): the target table comes from the file's own recorded tier and
environment, set when it was written.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			if _, err := os.Stat(input); os.IsNotExist(err) {
				return fmt.Errorf("input file not found: %s", input)
			}
			openFn := func(tier, env string) (store.Store, string, error) {
				return openStore(d, tier, env)
			}
			return runBackupImport(cmd.Context(), input, backup.ImportOptions{
				DryRun:    dryRun,
				Overwrite: overwrite,
				UpdatedBy: callerIdentity(cmd.Context(), d),
			}, d.log, openFn)
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "Path to backup JSON file (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate and diff without writing")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite items regardless of stored version")
	return cmd
}

// runBackupImport reads the backup file at input, resolves its target table
// from the file's OWN metadata.tier/metadata.environment (see backup_export.go
// and internal/backup/format.go's Metadata.Tier doc) via openStoreFn, and
// imports it. openStoreFn is injected so this is testable against a fake
// store without touching DynamoDB.
func runBackupImport(
	ctx context.Context,
	input string,
	opts backup.ImportOptions,
	log logger.Logger,
	openStoreFn func(tier, env string) (store.Store, string, error),
) error {
	raw, err := os.ReadFile(input) //nolint:gosec // path is caller-supplied CLI argument, same as platform-configctl's backup import
	if err != nil {
		return fmt.Errorf("read file %s: %w", input, err)
	}

	var bf backup.BackupFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return fmt.Errorf("parse backup file: %w", err)
	}

	st, table, err := openStoreFn(bf.Metadata.Tier, bf.Metadata.Environment)
	if err != nil {
		return fmt.Errorf("resolve target table from backup metadata (tier=%q env=%q): %w",
			bf.Metadata.Tier, bf.Metadata.Environment, err)
	}

	importer := backup.NewImporter(st)
	result, err := importer.Import(ctx, &bf, opts)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	return reportImportResult(log, opts.DryRun, table, result)
}

func reportImportResult(log logger.Logger, dryRun bool, table string, result *backup.ImportResult) error {
	if log == nil {
		return nil
	}
	if dryRun {
		log.Info("vault dry-run complete",
			zap.String("table", table),
			zap.Int("would-write", result.Written),
			zap.Int("skipped", result.Skipped),
		)
		return nil
	}

	log.Info("vault import complete",
		zap.String("table", table),
		zap.Int("written", result.Written),
		zap.Int("skipped", result.Skipped),
		zap.Int("failed", result.Failed),
	)

	if result.Failed > 0 {
		for _, e := range result.Errors {
			log.Error("item failed", zap.Error(e))
		}
		return fmt.Errorf("%d items failed to import", result.Failed)
	}
	return nil
}
