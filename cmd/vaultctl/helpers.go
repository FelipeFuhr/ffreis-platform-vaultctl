package main

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/spf13/cobra"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"

	"github.com/ffreis/platform-vaultctl/internal/vaulttier"
)

// openStore validates tier+env and returns a Store bound to the single
// DynamoDB table they resolve to. Every command that touches vault data
// calls this first, using its own <tier> positional arg and --env flag —
// there is no --table escape hatch, deliberately: tier+env are the only way
// to select a table.
func openStore(d *deps, tier, env string) (store.Store, string, error) {
	table, err := vaulttier.TableName(tier, env)
	if err != nil {
		return nil, "", err
	}
	client := dynamodb.NewFromConfig(d.awsCfg)
	return store.NewDynamoStore(client, table), table, nil
}

// addEnvFlag registers the required --env flag on cmd. Unlike
// platform-configctl's --project/--env (which fall back to --profile),
// --env has no fallback of any kind here — see root.go's applyProfileRegion
// doc for why a profile must never be able to supply it.
func addEnvFlag(cmd *cobra.Command, env *string) {
	cmd.Flags().StringVar(env, flagEnv, "", "Environment: dev or prod (required, no default)")
	_ = cmd.MarkFlagRequired(flagEnv)
}

// writeSecretFile writes data to path via writeFile and then explicitly
// chmods it to mode. This extra chmod is not redundant: os.WriteFile's own
// doc says plainly that its mode argument only applies when CREATING a new
// file — "otherwise WriteFile truncates it before writing, without changing
// permissions." If path already exists with a looser mode (e.g. left over
// from a run under a different umask, or created by some other tool), a
// bare writeFile(path, data, 0o600) call silently reuses that looser mode
// while still telling the caller it wrote "mode 0600". For a command whose
// whole job is writing decrypted secret material to disk, that is exactly
// the kind of silent leak this vault exists to prevent — so every command
// that writes secret-bearing output to a file goes through this helper,
// never a bare writeFile call, and the chmod is unconditional rather than
// "only when the file didn't already exist" so there is nothing to get
// wrong about detecting which case applies.
func writeSecretFile(
	writeFile func(string, []byte, os.FileMode) error,
	chmod func(string, os.FileMode) error,
	path string,
	data []byte,
	mode os.FileMode,
) error {
	if err := writeFile(path, data, mode); err != nil {
		return err
	}
	return chmod(path, mode)
}
