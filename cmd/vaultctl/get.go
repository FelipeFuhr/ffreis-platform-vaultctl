package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/crypto"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/guard"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"

	"github.com/ffreis/platform-vaultctl/internal/vaulttier"
)

func newGetCmd(d *deps) *cobra.Command {
	var env string
	var reveal bool

	cmd := &cobra.Command{
		Use:   "get <tier> <key>",
		Short: "Get a secret (metadata + fingerprint only, unless --reveal is set)",
		Long: `get prints secret metadata and a one-way fingerprint by default.

The fingerprint is the first 8 bytes of sha256(plaintext), hex-encoded — the
same fingerprint logic platform-configctl's own 'secret get' uses. It lets an
operator confirm "is this the secret I think it is" without the plaintext
ever being displayed.

Pass --reveal to print the actual plaintext value. --reveal is refused
outright when ` + envNoReveal + ` is set to a truthy value (1/true/yes/on) —
a kill switch for the case where stdout is not a safe place for a secret to
land, such as an AI agent session whose transcript is persisted. Use 'exec'
or 'export-env' instead when that's the case.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, key := args[0], args[1]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runGet(cmd.Context(), st, d.secretKey, tier, key, env, reveal, cmd.OutOrStdout())
		},
	}

	addEnvFlag(cmd, &env)
	cmd.Flags().BoolVar(&reveal, flagReveal, false, "Decrypt and print the plaintext value")
	return cmd
}

func runGet(
	ctx context.Context,
	st store.Store,
	secretKey, tier, key, env string,
	reveal bool,
	stdout io.Writer,
) error {
	if err := requireSecretKey(secretKey); err != nil {
		return err
	}
	// Checked before any decrypt is attempted: the kill switch refuses the
	// whole reveal path outright, not just the final print.
	if reveal && guard.EnvTruthy(envNoReveal) {
		return fmt.Errorf(
			"--reveal refused: %s is set — this environment has disabled printing secret plaintext "+
				"(use 'exec' or 'export-env' instead, or unset %s to override)",
			envNoReveal, envNoReveal,
		)
	}

	item, err := getVaultItem(ctx, st, env, key)
	if err != nil {
		return err
	}

	plaintext, err := decryptVaultItem(secretKey, tier, env, item)
	if err != nil {
		return err
	}
	fingerprint := guard.Fingerprint(plaintext)

	displayValue := "***"
	if reveal {
		displayValue = string(plaintext)
	}

	return writeGetOutput(stdout, item, displayValue, fingerprint)
}

// getVaultItem reads the item keyed by PROJECT#vault#ENV#{env}/SECRET#{key}
// from st — st is already bound to the tier-specific table by openStore, so
// only env (not tier) is part of the store lookup itself.
func getVaultItem(ctx context.Context, st store.Store, env, key string) (*store.Item, error) {
	item, err := st.Get(ctx, vaultProject, env, store.ItemTypeSecret, key)
	if err == nil {
		return item, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, &ExitError{Code: exitNotFound}
	}
	return nil, fmt.Errorf("get secret: %w", err)
}

// decryptVaultItem decrypts item's ciphertext with the currently configured
// passphrase. Always called by 'get' — even without --reveal — because the
// fingerprint is computed from the plaintext. keyName binds tier into the
// AAD (see vaulttier.AADKey) so ciphertext cannot be transplanted between
// tiers under the same key name.
func decryptVaultItem(secretKey, tier, env string, item *store.Item) ([]byte, error) {
	enc, err := crypto.NewAESGCMEncryptor(secretKey, vaultProject, env, vaulttier.AADKey(tier, item.Key))
	if err != nil {
		return nil, err
	}
	plaintext, err := enc.Decrypt([]byte(item.Value), item.KeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return plaintext, nil
}

func writeGetOutput(w io.Writer, item *store.Item, displayValue, fingerprint string) error {
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "key:", item.Key)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "value:", displayValue)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "fingerprint:", fingerprint)
	_, _ = fmt.Fprintf(w, "%-13s%d\n", "version:", item.Version)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "updated_at:", item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "updated_by:", item.UpdatedBy)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "key_id:", item.KeyID)
	return nil
}
