package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/crypto"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/guard"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"

	"github.com/ffreis/platform-vaultctl/internal/vaulttier"
)

func newPutCmd(d *deps) *cobra.Command {
	var env string

	cmd := &cobra.Command{
		Use:   "put <tier> <key>",
		Short: "Put a secret value — reads plaintext from stdin to avoid shell history",
		Long: `put reads the secret value from stdin, same discipline as
platform-configctl's 'secret set': never from a CLI argument, to avoid shell
history and process-listing leakage.

An empty, whitespace-only, or bare "-" value is refused outright — both are
writes that would otherwise "succeed" while storing garbage, undetected.

Example:
  echo -n "s3cr3t" | vaultctl put identity github-pat --env prod`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, key := args[0], args[1]
			st, _, err := openStore(d, tier, env)
			if err != nil {
				return err
			}
			return runPut(cmd.Context(), st, d.log, d.secretKey, tier, key, env, callerIdentity(cmd.Context(), d), os.Stdin)
		},
	}

	addEnvFlag(cmd, &env)
	return cmd
}

func runPut(
	ctx context.Context,
	st store.Store,
	log logger.Logger,
	secretKey, tier, key, env, updatedBy string,
	stdin io.Reader,
) error {
	if err := requireSecretKey(secretKey); err != nil {
		return err
	}

	plaintext, err := readVaultValueFromStdin(stdin)
	if err != nil {
		return err
	}

	ciphertext, keyID, err := encryptVaultValue(secretKey, tier, env, key, plaintext)
	if err != nil {
		return err
	}

	version, createdAt, err := existingVaultVersion(ctx, st, env, key)
	if err != nil {
		return err
	}

	item := buildVaultItem(env, key, ciphertext, keyID, version, createdAt, updatedBy)
	if err := st.Set(ctx, item); err != nil {
		return fmt.Errorf("put secret: %w", err)
	}

	if log != nil {
		log.Info("secret put",
			zap.String("tier", tier),
			zap.String("env", env),
			zap.String("key", key),
			zap.String("key_id", keyID),
		)
	}
	return nil
}

// readVaultValueFromStdin reads plaintext from stdin and refuses an empty,
// whitespace-only, or bare "-" value — see internal/guard for the two
// incidents that motivated this.
func readVaultValueFromStdin(stdin io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read secret from stdin: %w", err)
	}
	// Trim a single trailing newline (common from echo | piping), same as
	// platform-configctl's readStdin.
	trimmed := trimTrailingNewline(raw)
	if err := guard.ValidateSecretValue(trimmed); err != nil {
		return nil, err
	}
	return trimmed, nil
}

func trimTrailingNewline(raw []byte) []byte {
	s := string(raw)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return []byte(s)
}

// encryptVaultValue binds tier into the AAD via vaulttier.AADKey — see that
// function's doc for why (prevents transplanting ciphertext between tiers
// that happen to share a key name).
func encryptVaultValue(secretKey, tier, env, key string, plaintext []byte) ([]byte, string, error) {
	enc, err := crypto.NewAESGCMEncryptor(secretKey, vaultProject, env, vaulttier.AADKey(tier, key))
	if err != nil {
		return nil, "", err
	}
	ciphertext, keyID, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt secret: %w", err)
	}
	return ciphertext, keyID, nil
}

func existingVaultVersion(ctx context.Context, st store.Store, env, key string) (int64, time.Time, error) {
	existing, err := st.Get(ctx, vaultProject, env, store.ItemTypeSecret, key)
	if err != nil && err != store.ErrNotFound { //nolint:errorlint // sentinel compared directly, mirrors platform-configctl's existingSecretVersion
		return 0, time.Time{}, fmt.Errorf("get existing: %w", err)
	}
	if existing == nil {
		return 0, time.Time{}, nil
	}
	return existing.Version, existing.CreatedAt, nil
}

func buildVaultItem(env, key string, ciphertext []byte, keyID string, version int64, createdAt time.Time, updatedBy string) *store.Item {
	h := sha256.Sum256(ciphertext)
	return &store.Item{
		Project:   vaultProject,
		Env:       env,
		Key:       key,
		Value:     string(ciphertext),
		Type:      store.ItemTypeSecret,
		Encrypted: true,
		KeyID:     keyID,
		Version:   version,
		Checksum:  fmt.Sprintf(checksumFormatSHA256, h),
		CreatedAt: createdAt,
		UpdatedBy: updatedBy,
	}
}
