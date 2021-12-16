package rangeproof

import (
	"encoding/base64"
	"errors"
	"math/big"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/vosbor/dusk-crypto/rangeproof/pedersen"
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
	CA Commitment
	CApC Commitment
	B int64
	CB Commitment
	CBpC Commitment
	CC Commitment
	C string
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
   Recalculate the commitment and compare.
*/
func VerifyCommit(v int64, c Commitment) bool {

	genData := []byte("vosbor.BulletProof.v1")
	ped := pedersen.New(genData)
	ped.BaseVector.Compute(uint32((M * N)))

	var amount ristretto.Scalar
	amount.SetBigInt(big.NewInt(v))

	return ped.VerifyCommitment(amount, c.PedersenCommitment)
}

/*
    GenProofs computes a zero knowledge proofs that shows
v belongs to the interval [a, b) and is the correctly tied
together with the commitment c.
*/
func GenProof(v int64, c Commitment, a int64, b int64) (RangeProof, error) {

	if !VerifyCommit(v, c) {
		return RangeProof{}, errors.New("Invalid commitment")
	}

	amounts := []ristretto.Scalar{}
	commitments := make([]pedersen.Commitment, 0, M)

	// convert commitment to base64 value, blinding factor remains hidden
	c_v := base64.StdEncoding.EncodeToString(c.PedersenCommitment.Commit.Bytes())

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
	b2.Sub(b2, big.NewInt(1))

	bigv_a := big.NewInt(a)
	bigv_a = bigv_a.Sub(big.NewInt(v), bigv_a)

	bb := big.NewInt(b)
	bigv_b := b2.Sub(b2, bb)
	bigv_b = bigv_b.Add(big.NewInt(v), bigv_b)


	var amount_b ristretto.Scalar
	var amount_a ristretto.Scalar
	amount_b.SetBigInt(bigv_b)
	amount_a.SetBigInt(bigv_a)

	c_b := ped_b.CommitToScalar(amount_b)
	c_a := ped_a.CommitToScalar(amount_a)
	c_cb := pedersen.Add(c.PedersenCommitment, c_b)
	c_ca := pedersen.Sub(c.PedersenCommitment, c_a)

	amounts = append(amounts, amount_b)
	amounts = append(amounts, amount_a)
	commitments = append(commitments, c_cb)
	commitments = append(commitments, c_ca)

	p, err := Prove(amounts, commitments, true)

	output := RangeProof {
		P: p,
		A: a,
		CA: Commitment{ PedersenCommitment: c_a },
		CApC: Commitment{ PedersenCommitment: c_ca },
		B: b,
		CB: Commitment{ PedersenCommitment: c_b },
		CBpC: Commitment{ PedersenCommitment: c_cb },
		CC: c,
		C: c_v,
	}

	return output, err

}

/*
    VerifyProof takes as input a zero knowledge proofs and
returns true if a valid proof, and false otherwise.
*/
func VerifyProof(p RangeProof) (err error) {

	if !(p.CApC.PedersenCommitment.Equals(pedersen.Sub(
			p.CC.PedersenCommitment,
			p.CA.PedersenCommitment))) {
		return errors.New("Commitment is inconsistent with lower bound A.")
	}
	if !(p.CBpC.PedersenCommitment.Equals(pedersen.Add(
		p.CC.PedersenCommitment,
		p.CB.PedersenCommitment))) {
		return errors.New("Commitment is inconsistent with lower bound B.")
	}

	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	Verify(p.P)
	return err
}
