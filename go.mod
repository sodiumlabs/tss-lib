module github.com/sodiumlabs/tss-lib

go 1.19

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ipfs/go-log v1.0.5
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	google.golang.org/protobuf v1.28.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/ipfs/go-log/v2 v2.1.3 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.5.0 // indirect
	golang.org/x/sys v0.0.0-20210917161153-d61c044b1678 // indirect
	golang.org/x/tools v0.1.5 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/tools v0.0.1-2020.1.4 // indirect
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
