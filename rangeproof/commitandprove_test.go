package rangeproof

import (
	"bytes"
	"fmt"
	"testing"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vosbor/dusk-crypto/rangeproof/pedersen"
)

func TestCommitSerialization(t *testing.T) {
	fmt.Println("Testing serialization.")
	a := int64(42)
	ca, erra := Commit(a)
	buffer := new(bytes.Buffer)
	err := ca.PedersenCommitment.Encode(buffer)
	c := pedersen.Commitment{}
	err = c.Decode(buffer)
	c.BlindingFactor = ca.PedersenCommitment.BlindingFactor
	res := VerifyCommit(a, Commitment{PedersenCommitment: c})
	require.True(t, res)
	require.Nil(t, erra)
	require.Nil(t, err)
}

func TestCommitAddition(t *testing.T) {
	fmt.Println("Testing commit addition.")
	a := int64(42)
	b := int64(41)
	ca, erra := Commit(a)
	cb, errb := Commit(b)
	cc := pedersen.Add(ca.PedersenCommitment, cb.PedersenCommitment)
	commitab := Commitment{
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

func TestPositiveFlow1(t *testing.T) {
	fmt.Println("Testing valid proof construction.")
	n := int64(40)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}

func TestPositiveFlow2(t *testing.T) {
	fmt.Println("Testing valid proof construction (inclusion left).")
	n := int64(0)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 0, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}

func TestPositiveFlow3(t *testing.T) {
	fmt.Println("Testing valid proof construction (inclusion right).")
	n := int64(99)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 0, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}

func TestPositiveFlow4(t *testing.T) {
	fmt.Println("Testing valid proof construction (inclusion non-zero left).")
	n := int64(20)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}


func TestNegativeFlow1(t *testing.T) {
	fmt.Println("Testing invalid proof construction.")
	n := int64(41)
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
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow4(t * testing.T) {
	fmt.Println("Testing invalid commitment.")
	n := int64(42)
	c, errc := Commit(n)
	c1, errc1 := Commit(1)
	c.PedersenCommitment = pedersen.Add(c1.PedersenCommitment, c.PedersenCommitment)
	p, errp := GenProof(n, c, 20, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errc1)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow5(t * testing.T) {
	fmt.Println("Testing invalid lower bound commitment.")
	n := int64(42)
	c, errc := Commit(n)
	c1, errc1 := Commit(1)
	p, errp := GenProof(n, c, 20, 100)
	p.CA.PedersenCommitment = pedersen.Add(c1.PedersenCommitment, p.CA.PedersenCommitment)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errc1)
	require.Nil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow6(t * testing.T) {
	fmt.Println("Testing invalid upper bound commitment.")
	n := int64(42)
	c, errc := Commit(n)
	c1, errc1 := Commit(1)
	p, errp := GenProof(n, c, 20, 100)
	p.CB.PedersenCommitment = pedersen.Add(c1.PedersenCommitment, p.CB.PedersenCommitment)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errc1)
	require.Nil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow7(t *testing.T) {
	fmt.Println("Testing invalid proof construction.")
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 41)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow8(t *testing.T) {
	fmt.Println("Testing invalid proof construction.")
	n := int64(-1)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 41)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}
