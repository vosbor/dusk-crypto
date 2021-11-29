package rangeproof

import (
	"math/big"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/dusk-network/dusk-crypto/rangeproof/pedersen"
)

/*
    Commitment struct is responsible for storing
a commitment that is compatible with proving algorithm.
It must be possible to serialize it into bytes and
deserialized back into the correct format.
*/
type Commitment struct {
	PedersenCommitment pedersen.Commitment
}

/*
    RangeProof stores a zero knowledge proof that
a secret belongs to a certain interval.
*/
type RangeProof struct {
	P Proof
	A int64
	B int64
}

/*
    Commit function is responsible for generation of
commitment to secret value v.
*/
func Commit(v int64) (Commitment, error) {

	genData := []byte("vosbor.BulletProof.v1")
	ped := pedersen.New(genData)
	ped.BaseVector.Compute(uint32((M * N)))

	var amount ristretto.Scalar
	amount.SetBigInt(big.NewInt(v))
	c := ped.CommitToScalar(amount)

	output := Commitment{
		PedersenCommitment: c,
	}

	return output, nil
}

/*
    GenProofs computes a zero knowledge proofs that shows
v belongs to the interval [a, b) and is the correctly tied
together with the commitment c.
*/
func GenProof(v int64, c Commitment, a int64, b int64) (RangeProof, error) {
	amounts := []ristretto.Scalar{}
	commitments := make([]pedersen.Commitment, 0, M)

	// N is number of bits in range
	// So amount will be between 0...2^(N-1)
	const N = 64

	genData_b := []byte("vosbor.BulletProof.b")
	ped_b := pedersen.New(genData_b)
	ped_b.BaseVector.Compute(uint32((M * N)))
	genData_a := []byte("vosbor.BulletProof.a")
	ped_a := pedersen.New(genData_a)
	ped_a.BaseVector.Compute(uint32((M * N)))

	b2 := big.NewInt(2)
	bn := big.NewInt(N)

	b2.Exp(b2, bn, nil)

	bigv_b := big.NewInt(v)
	bigv_a := big.NewInt(v)
	bb := big.NewInt(b)
	ba := big.NewInt(a)
	bigv_b = bigv_b.Sub(bigv_b, bb)
	bigv_b = bigv_b.Add(bigv_b, b2)
	bigv_a = bigv_a.Sub(bigv_a, ba)

	var amount_b ristretto.Scalar
	var amount_a ristretto.Scalar
	amount_b.SetBigInt(bigv_b)
	amount_a.SetBigInt(bigv_a)

	c_b := ped_b.CommitToScalar(amount_b)
	c_a := ped_a.CommitToScalar(amount_a)

	amounts = append(amounts, amount_b)
	amounts = append(amounts, amount_a)
	commitments = append(commitments, c_b)
	commitments = append(commitments, c_a)

	p, err := Prove(amounts, commitments, true)

	output := RangeProof{
		P: p,
		A: a,
		B: b,
	}

	return output, err

}

/*
    VerifyProof takes as input a zero knowledge proofs and
returns true if a valid proof, and false otherwise.
*/
func VerifyProof(p RangeProof) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	Verify(p.P)
	return err
}
