// Command vaultctl is the credential-vault CLI: get/put/exec/export-env/
// list/delete/backup against the fleet's identity/repo/root DynamoDB vault
// tables, plus the leak-control primitives (fingerprint-only get, a reveal
// kill switch, exec/export-env for injecting a secret without ever printing
// it) that used to live on platform-configctl before being split out here.
//
// vaultctl is deliberately a separate binary from platform-configctl: it
// owns the credential-vault surface as its own identity rather than blurring
// it into a tool named "config". It reuses platform-configctl's
// internal/store, internal/crypto, internal/logger, and internal/profile
// packages directly (Go's internal/ visibility permits this since both
// binaries share the same module root) — no forked crypto, no second copy
// of the storage layer.
package main

import "os"

func main() {
	os.Exit(Execute())
}
