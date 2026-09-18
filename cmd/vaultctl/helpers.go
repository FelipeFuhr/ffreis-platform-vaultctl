package main

import (
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
