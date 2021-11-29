package rangeproof

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPositiveFlow(t *testing.T) {
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.Nil(t, errp)
	require.Nil(t, errv)
}

func TestNegativeFlow1(t *testing.T) {
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 20, 41)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}

func TestNegativeFlow2(t *testing.T) {
	n := int64(42)
	c, errc := Commit(n)
	p, errp := GenProof(n, c, 43, 100)
	errv := VerifyProof(p)
	require.Nil(t, errc)
	require.NotNil(t, errp)
	require.NotNil(t, errv)
}
