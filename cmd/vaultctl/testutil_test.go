package main

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"go.uber.org/zap"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/logger"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// noopChmod is a fake chmod for tests whose writeFile is also faked (so
// there is no real file on disk for a real os.Chmod to act on).
func noopChmod(string, os.FileMode) error { return nil }

// unreachableAWSConfig points a real (non-fake) AWS config at a local port
// nothing listens on, with retries disabled. Used to exercise a command's
// RunE closure all the way through its real openStore + store call — the
// call fails fast (connection refused, no retry backoff) instead of
// reaching real AWS, so tests stay hermetic and fast while still covering
// the closure's success-continuation line (unlike fakeStore, which can only
// be injected below the cobra/openStore layer).
func unreachableAWSConfig() aws.Config {
	return aws.Config{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String("http://127.0.0.1:1"),
		Credentials:      credentials.NewStaticCredentialsProvider("local", "local", ""),
		RetryMaxAttempts: 1,
	}
}

const testSecretKey = "01234567890123456789012345678901"

type noopLogger struct{}

func (noopLogger) Info(string, ...zap.Field)  {}
func (noopLogger) Warn(string, ...zap.Field)  {}
func (noopLogger) Error(string, ...zap.Field) {}
func (noopLogger) Debug(string, ...zap.Field) {}
func (noopLogger) With(...zap.Field) logger.Logger {
	return noopLogger{}
}

type fakeStore struct {
	getFn    func(ctx context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error)
	setFn    func(ctx context.Context, item *store.Item) error
	listFn   func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error)
	deleteFn func(ctx context.Context, project, env string, itemType store.ItemType, key string) error
}

func (f fakeStore) Get(ctx context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error) {
	if f.getFn == nil {
		panic("unexpected store.Get call")
	}
	return f.getFn(ctx, project, env, itemType, key)
}
func (f fakeStore) Set(ctx context.Context, item *store.Item) error {
	if f.setFn == nil {
		panic("unexpected store.Set call")
	}
	return f.setFn(ctx, item)
}
func (f fakeStore) List(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
	if f.listFn == nil {
		panic("unexpected store.List call")
	}
	return f.listFn(ctx, project, env, itemType)
}
func (f fakeStore) Delete(ctx context.Context, project, env string, itemType store.ItemType, key string) error {
	if f.deleteFn == nil {
		panic("unexpected store.Delete call")
	}
	return f.deleteFn(ctx, project, env, itemType, key)
}
func (f fakeStore) ListProjects(context.Context) ([]string, error) {
	panic("unexpected store.ListProjects call")
}

// encryptedVaultItem builds a real, tier-bound-AAD encrypted store.Item for
// key, exactly as runPut would produce, for tests that need a real
// ciphertext to decrypt through runGet/runExec/runExportEnv.
func encryptedVaultItem(tier, env, key, plaintext string) *store.Item {
	ciphertext, keyID, err := encryptVaultValue(testSecretKey, tier, env, key, []byte(plaintext))
	if err != nil {
		panic(err)
	}
	return &store.Item{Key: key, Value: string(ciphertext), KeyID: keyID, Version: 1}
}
