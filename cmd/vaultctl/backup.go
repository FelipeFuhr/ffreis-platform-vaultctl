package main

import "github.com/spf13/cobra"

func newBackupCmd(d *deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Export and import vault snapshots",
	}
	cmd.AddCommand(
		newBackupExportCmd(d),
		newBackupImportCmd(d),
	)
	return cmd
}
