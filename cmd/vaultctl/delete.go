package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

func newDeleteCmd(d *deps) *cobra.Command {
	var env string

	cmd := &cobra.Command{
		Use:   "delete <tier> <key>",
		Short: "Delete a secret (idempotent)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, key := args[0], args[1]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runDelete(cmd.Context(), st, d.log, tier, key, env)
		},
	}

	addEnvFlag(cmd, &env)
	return cmd
}

func runDelete(ctx context.Context, st store.Store, log logger.Logger, tier, key, env string) error {
	_, err := st.Get(ctx, vaultProject, env, store.ItemTypeSecret, key)
	if err == store.ErrNotFound { //nolint:errorlint // sentinel compared directly, mirrors platform-configctl's newSecretDeleteCmd
		if log != nil {
			log.Warn("secret not found, nothing deleted",
				zap.String("tier", tier),
				zap.String("env", env),
				zap.String("key", key),
			)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	if err := st.Delete(ctx, vaultProject, env, store.ItemTypeSecret, key); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	if log != nil {
		log.Info("secret deleted",
			zap.String("tier", tier),
			zap.String("env", env),
			zap.String("key", key),
		)
	}
	return nil
}
