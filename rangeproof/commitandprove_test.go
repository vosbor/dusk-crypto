package rangeproof

import (
	"fmt"
	"testing"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vosbor/dusk-crypto/rangeproof/pedersen"
)

func TestCommitAddition(t *testing.T) {
	fmt.Println("Testing commit addition.")
	a := int64(42)
	b := int64(41)
	ca, erra := Commit(a)
	cb, errb := Commit(b)
	cc := pedersen.Add(ca.PedersenCommitment, cb.PedersenCommitment)
	commitab := Commitment {
		PedersenCommitment: cc,
	}
	assert.Equal(t, VerifyCommit(a+b, commitab), true)
	require.Nil(t, erra)
	require.Nil(t, errb)
}

func TestCommitPositiveFlow(t *testing.T) {
	fmt.Println("Testing valid commit construction.")
	n := int64(42)
	c, errc := Commit(n)
	assert.Equal(t, VerifyCommit(n, c), true)
	require.Nil(t, errc)
}

func TestPositiveFlow(t *testing.T) {
	fmt.Println("Testing valid proof construction.")
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}

func TestNegativeFlow1(t *testing.T) {
	fmt.Println("Testing invalid proof construction.")
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 41)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow2(t *testing.T) {
	fmt.Println("Testing invalid proof construction.")
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 43, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow3(t *testing.T) {
	fmt.Println("Testing invalid commit for proof construction.")
	n := int64(42)
	c, errc := Commit(n)
	blind := ristretto.Scalar{}
	blind.Rand()
	c.PedersenCommitment.BlindingFactor = blind
	p, errp := GenProof(n, c, 20, 41)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}
