module github.com/vosbor/dusk-crypto

go 1.12

require (
	github.com/OneOfOne/xxhash v1.2.5
	github.com/bwesterb/go-ristretto v1.1.0
	github.com/dusk-network/bn256 v0.5.1-lattices
	github.com/dusk-network/dusk-crypto v0.1.3
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d
)

replace github.com/dusk-network/dusk-crypto => github.com/vosbor/dusk-crypto v1.1.12
