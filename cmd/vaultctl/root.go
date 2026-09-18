// vaultctl's command tree lives in package main (unlike platform-configctl,
// which splits a thin cmd/platform-configctl/main.go from a testable
// top-level cmd package) — a single package is enough for a smaller,
// vault-focused binary, and go test exercises package main here exactly as
// it already does for platform-configctl's own main_test.go. The same
// injected-dependencies-no-globals discipline applies: deps and
// globalFlags are built once in buildRoot and threaded through, never
// package-level vars.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/profile"
)

// version is set via -ldflags at build time (see the Makefile's
// build-vaultctl target). It has no dedicated 'version' subcommand — unlike
// platform-configctl — since the given command surface doesn't call for
// one; it still flows into backup exports' Metadata.ToolVersion.
var version string

// deps holds all resolved runtime dependencies that do NOT depend on which
// <tier>/--env a command targets. Unlike platform-configctl (one global
// table, resolved once), vaultctl resolves a DIFFERENT physical DynamoDB
// table per tier+env, so the Store itself cannot be built here — see
// openStore, called by each command's RunE once it knows its own tier/env.
type deps struct {
	log       logger.Logger
	awsCfg    aws.Config
	secretKey string           // from VAULTCTL_SECRET_KEY; empty means unset
	profile   *profile.Profile // resolved --profile defaults, nil unless --profile was set
}

// globalFlags holds the values bound to top-level persistent flags.
type globalFlags struct {
	region   string
	logLevel string
	profile  string
}

const (
	exitOK       = 0
	exitError    = 1
	exitNotFound = 2
)

// ExitError carries an explicit process exit code alongside the error that
// caused it, mirroring platform-configctl's own ExitError.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Execute is the entrypoint for the CLI. It builds the command tree and runs it.
func Execute() int {
	return executeCommand(buildRoot(), os.Stderr)
}

func executeCommand(cmd *cobra.Command, stderr io.Writer) int {
	if err := cmd.Execute(); err != nil {
		if message := err.Error(); message != "" {
			_, _ = io.WriteString(stderr, "error: "+message+"\n")
		}
		return exitCodeForError(err)
	}
	return exitOK
}

func exitCodeForError(err error) int {
	var exitErr *ExitError
	if errors.As(err, &exitErr) && exitErr != nil && exitErr.Code != 0 {
		return exitErr.Code
	}
	return exitError
}

func buildRoot() *cobra.Command {
	gf := &globalFlags{}
	d := &deps{}

	root := &cobra.Command{
		Use:   "vaultctl",
		Short: "Credential vault CLI for the identity/repo/root DynamoDB vault tables",
		Long: `vaultctl manages secrets in the fleet's credential vault.

Every command takes an explicit <tier> (identity, repo, or root) and
--env (dev or prod, no default) — there is no --table and no --project;
tier+env alone resolve which of the six vault tables a command targets.
Set VAULTCTL_SECRET_KEY before any get/put/exec/export-env/backup call.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initDeps(cmd.Context(), gf, d)
		},
	}

	root.PersistentFlags().StringVar(&gf.region, "region", "", "AWS region (overrides AWS_DEFAULT_REGION)")
	root.PersistentFlags().StringVar(&gf.logLevel, "log-level", "", "Log level: debug, info, warn, error (overrides VAULTCTL_LOG_LEVEL)")
	root.PersistentFlags().StringVar(&gf.profile, "profile", "",
		"Named profile from ~/.config/vaultctl/profiles.yaml supplying a default --region (never --env: an accidental "+
			"prod default is exactly what this vault exists to prevent)")

	root.AddCommand(
		newGetCmd(d),
		newPutCmd(d),
		newExecCmd(d),
		newExportEnvCmd(d),
		newListCmd(d),
		newDeleteCmd(d),
		newBackupCmd(d),
		newWhoamiCmd(d),
	)

	return root
}

// initDeps resolves every dependency that is independent of which
// <tier>/--env a specific command targets: the logger, AWS config (used to
// build a per-command DynamoDB client via openStore), the secret passphrase,
// and the active --profile, if any.
func initDeps(ctx context.Context, gf *globalFlags, d *deps) error {
	prof, err := resolveProfile(gf.profile)
	if err != nil {
		return err
	}
	d.profile = prof

	// Only --region is ever filled in from a profile — see applyProfileRegion.
	region := gf.region
	applyProfileRegion(prof, &region)

	logLevel := gf.logLevel
	if logLevel == "" {
		logLevel = os.Getenv(envLogLevel)
	}
	if logLevel == "" {
		logLevel = "info"
	}

	log, err := logger.New(logLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	awsOpts := []func(*config.LoadOptions) error{}
	if region != "" {
		awsOpts = append(awsOpts, config.WithRegion(region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	d.log = log
	d.awsCfg = awsCfg
	d.secretKey = os.Getenv(envPassphrase)
	return nil
}

// applyProfileRegion fills region from the active --profile, if any, but
// only when the caller left it empty. Deliberately the ONLY profile field
// vaultctl ever applies: --env has no default by design (see buildRoot's
// --profile help text), and there is no --table/--project to fill.
func applyProfileRegion(prof *profile.Profile, region *string) {
	if prof == nil {
		return
	}
	if *region == "" && prof.Region != "" {
		*region = prof.Region
	}
}

// resolveProfile loads and resolves the named profile, if any. An empty name
// is a no-op (returns nil, nil). Once a name is given, a missing profiles
// file or a name absent from it is a clear error, never a silent no-op.
func resolveProfile(name string) (*profile.Profile, error) {
	if name == "" {
		return nil, nil
	}
	path, err := profile.DefaultPath("vaultctl")
	if err != nil {
		return nil, err
	}
	return profile.Resolve(path, name)
}

// requireSecretKey returns an error if secretKey is empty. Call this before
// any operation that decrypts or encrypts.
func requireSecretKey(secretKey string) error {
	if secretKey == "" {
		return fmt.Errorf("%s environment variable is required for this operation", envPassphrase)
	}
	return nil
}

// callerIdentity returns the IAM caller identity ARN for use as updated_by
// and for 'whoami', reusing the AWS config initDeps already resolved.
func callerIdentity(ctx context.Context, d *deps) string {
	stsClient := sts.NewFromConfig(d.awsCfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	if out.Arn == nil {
		return "unknown"
	}
	return *out.Arn
}

// newWhoamiCmd prints the resolved IAM identity for diagnostics.
func newWhoamiCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print the resolved IAM caller identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			arn := callerIdentity(cmd.Context(), d)
			_, err := io.WriteString(cmd.OutOrStdout(), arn+"\n")
			return err
		},
	}
}
