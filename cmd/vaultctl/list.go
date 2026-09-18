package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newListCmd(d *deps) *cobra.Command {
	var env string

	cmd := &cobra.Command{
		Use:   "list <tier>",
		Short: "List secret keys in a tier (values are always masked)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier := args[0]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runList(cmd.Context(), st, env, cmd.OutOrStdout())
		},
	}

	addEnvFlag(cmd, &env)
	return cmd
}

func runList(ctx context.Context, st store.Store, env string, stdout io.Writer) error {
	items, err := st.List(ctx, vaultProject, env, store.ItemTypeSecret)
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s=***\n", item.Key); err != nil {
			return err
		}
	}
	return nil
}
