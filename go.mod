module github.com/ffreis/platform-vaultctl

go 1.25.8

// scan-fix(govulncheck:GO-2026-6218,GO-2026-6090,GO-2026-6088,GO-2026-5972,GO-2026-5026):
// go1.25.12's stdlib (net/url, crypto/tls, encoding/xml, encoding/asn1,
// net/http via x/net/idna) carries 5 vulnerabilities this repo's call graph
// reaches (callerIdentity's sts.Client.GetCallerIdentity, encryptVaultValue's
// crypto.AESGCMEncryptor.Encrypt) -- all fixed in go1.25.13. `make sec`
// (govulncheck ./...) failed the lefthook quality-gates job on this pin;
// bumping the toolchain resolves it. Same fix already applied in
// ffreis-platform-configctl's go.mod (the source of this pulled code).
toolchain go1.25.13

require (
	github.com/FelipeFuhr/ffreis-platform-configctl v0.0.0-20260918170453-47965e6f5962
	github.com/aws/aws-sdk-go-v2 v1.41.7
	github.com/aws/aws-sdk-go-v2/config v1.32.17
	github.com/aws/aws-sdk-go-v2/credentials v1.19.16
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.3
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.1
	github.com/spf13/cobra v1.10.2
	go.uber.org/zap v1.28.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.20.39 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.32.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.21 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
