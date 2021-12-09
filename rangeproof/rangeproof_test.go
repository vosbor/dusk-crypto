package rangeproof

import (
	"bytes"
	"io"
	"math/big"
	"math/rand"
	"reflect"
	"testing"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vosbor/dusk-crypto/rangeproof/fiatshamir"
	"github.com/vosbor/dusk-crypto/rangeproof/innerproduct"
	"github.com/vosbor/dusk-crypto/rangeproof/pedersen"
)

func TestProveBulletProof(t *testing.T) {

	p := generateProof(2, t)

	// Verify
	ok, err := Verify(*p)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, ok)

}

func TestEncodeDecode(t *testing.T) {
	p := generateProof(4, t)
	includeCommits := false

	buf := &bytes.Buffer{}
	err := p.Encode(buf, includeCommits)
	assert.Nil(t, err)

	var decodedProof Proof
	err = decodedProof.Decode(buf, includeCommits)
	assert.Nil(t, err)

	ok := decodedProof.Equals(*p, includeCommits)
	assert.True(t, ok)
}

func TestComputeMu(t *testing.T) {
	var one ristretto.Scalar
	one.SetOne()

	var expected ristretto.Scalar
	expected.SetBigInt(big.NewInt(2))

	res := computeMu(one, one, one)

	ok := expected.Equals(&res)

	assert.Equal(t, true, ok)
}

func generateProof(m int, t *testing.T) *Proof {

	// XXX: m must be a multiple of two due to inner product proof
	amounts := []ristretto.Scalar{}
	commitments := make([]pedersen.Commitment, 0, M)

	// N is number of bits in range
	// So amount will be between 0...2^(N-1)
	const N = 64

	genData := []byte("vosbor.BulletProof.v1")
	ped := pedersen.New(genData)
	ped.BaseVector.Compute(uint32((M * N)))

	for i := 0; i < m; i++ {

		var amount ristretto.Scalar
		n := rand.Int63()
		amount.SetBigInt(big.NewInt(n))
		c := ped.CommitToScalar(amount)

		amounts = append(amounts, amount)
		commitments = append(commitments, c)
	}

	// Prove
	p, err := Prove(amounts, commitments, true)
	require.Nil(t, err)
	return &p
}

func BenchmarkProve(b *testing.B) {

	var amount ristretto.Scalar

	genData := []byte("vosbor.BulletProof.v1")
	ped := pedersen.New(genData)
	ped.BaseVector.Compute(uint32((N)))
	commitments := make([]pedersen.Commitment, 0, M)

	amount.SetBigInt(big.NewInt(100000))
	c := ped.CommitToScalar(amount)

	commitments = append(commitments, c)

	for i := 0; i < 100; i++ {

		// Prove
		Prove([]ristretto.Scalar{amount}, commitments, false)
	}

}

func BenchmarkVerify(b *testing.B) {

	var amount ristretto.Scalar

	genData := []byte("vosbor.BulletProof.v1")
	ped := pedersen.New(genData)
	ped.BaseVector.Compute(uint32((N)))
	commitments := make([]pedersen.Commitment, 0, M)

	amount.SetBigInt(big.NewInt(100000))
	c := ped.CommitToScalar(amount)
	commitments = append(commitments, c)

	p, _ := Prove([]ristretto.Scalar{amount}, commitments, false)

	b.ResetTimer()

	for i := 0; i < 100; i++ {
		// Verify
		Verify(p)
	}

}

func TestProve(t *testing.T) {
	type args struct {
		v     []ristretto.Scalar
		c     []pedersen.Commitment
		debug bool
	}
	tests := []struct {
		name    string
		args    args
		want    Proof
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Prove(tt.args.v, tt.args.c, tt.args.debug)
			if (err != nil) != tt.wantErr {
				t.Errorf("Prove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Prove() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_computeA(t *testing.T) {
	type args struct {
		ped *pedersen.Pedersen
		aLs []ristretto.Scalar
		aRs []ristretto.Scalar
	}
	tests := []struct {
		name string
		args args
		want pedersen.Commitment
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeA(tt.args.ped, tt.args.aLs, tt.args.aRs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_computeS(t *testing.T) {
	type args struct {
		ped *pedersen.Pedersen
	}
	tests := []struct {
		name  string
		args  args
		want  pedersen.Commitment
		want1 []ristretto.Scalar
		want2 []ristretto.Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := computeS(tt.args.ped)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeS() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeS() got1 = %v, want %v", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("computeS() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func Test_computeYAndZ(t *testing.T) {
	type args struct {
		hs fiatshamir.HashCacher
	}
	tests := []struct {
		name  string
		args  args
		want  ristretto.Scalar
		want1 ristretto.Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := computeYAndZ(tt.args.hs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeYAndZ() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeYAndZ() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_computeX(t *testing.T) {
	type args struct {
		hs fiatshamir.HashCacher
	}
	tests := []struct {
		name string
		args args
		want ristretto.Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeX(tt.args.hs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeX() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_computeTaux(t *testing.T) {
	type args struct {
		x       ristretto.Scalar
		z       ristretto.Scalar
		t1Blind ristretto.Scalar
		t2Blind ristretto.Scalar
		vBlinds []pedersen.Commitment
	}
	tests := []struct {
		name string
		args args
		want ristretto.Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeTaux(tt.args.x, tt.args.z, tt.args.t1Blind, tt.args.t2Blind, tt.args.vBlinds); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeTaux() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_computeMu(t *testing.T) {
	type args struct {
		x     ristretto.Scalar
		alpha ristretto.Scalar
		rho   ristretto.Scalar
	}
	tests := []struct {
		name string
		args args
		want ristretto.Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeMu(tt.args.x, tt.args.alpha, tt.args.rho); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeMu() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_computeHprime(t *testing.T) {
	type args struct {
		H []ristretto.Point
		y ristretto.Scalar
	}
	tests := []struct {
		name string
		args args
		want []ristretto.Point
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeHprime(tt.args.H, tt.args.y); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("computeHprime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		p Proof
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_megacheckWithC(t *testing.T) {
	type args struct {
		ipproof *innerproduct.Proof
		mu      ristretto.Scalar
		x       ristretto.Scalar
		y       ristretto.Scalar
		z       ristretto.Scalar
		t       ristretto.Scalar
		taux    ristretto.Scalar
		w       ristretto.Scalar
		A       ristretto.Point
		G       ristretto.Point
		H       ristretto.Point
		S       ristretto.Point
		T1      ristretto.Point
		T2      ristretto.Point
		GVec    []ristretto.Point
		HVec    []ristretto.Point
		V       []pedersen.Commitment
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := megacheckWithC(tt.args.ipproof, tt.args.mu, tt.args.x, tt.args.y, tt.args.z, tt.args.t, tt.args.taux, tt.args.w, tt.args.A, tt.args.G, tt.args.H, tt.args.S, tt.args.T1, tt.args.T2, tt.args.GVec, tt.args.HVec, tt.args.V)
			if (err != nil) != tt.wantErr {
				t.Errorf("megacheckWithC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("megacheckWithC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProof_Encode(t *testing.T) {
	type fields struct {
		V        []pedersen.Commitment
		Blinders []ristretto.Scalar
		A        ristretto.Point
		S        ristretto.Point
		T1       ristretto.Point
		T2       ristretto.Point
		taux     ristretto.Scalar
		mu       ristretto.Scalar
		t        ristretto.Scalar
		IPProof  *innerproduct.Proof
	}
	type args struct {
		includeCommits bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantW   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proof{
				V:        tt.fields.V,
				Blinders: tt.fields.Blinders,
				A:        tt.fields.A,
				S:        tt.fields.S,
				T1:       tt.fields.T1,
				T2:       tt.fields.T2,
				taux:     tt.fields.taux,
				mu:       tt.fields.mu,
				t:        tt.fields.t,
				IPProof:  tt.fields.IPProof,
			}
			w := &bytes.Buffer{}
			if err := p.Encode(w, tt.args.includeCommits); (err != nil) != tt.wantErr {
				t.Errorf("Proof.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("Proof.Encode() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestProof_Decode(t *testing.T) {
	type fields struct {
		V        []pedersen.Commitment
		Blinders []ristretto.Scalar
		A        ristretto.Point
		S        ristretto.Point
		T1       ristretto.Point
		T2       ristretto.Point
		taux     ristretto.Scalar
		mu       ristretto.Scalar
		t        ristretto.Scalar
		IPProof  *innerproduct.Proof
	}
	type args struct {
		r              io.Reader
		includeCommits bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proof{
				V:        tt.fields.V,
				Blinders: tt.fields.Blinders,
				A:        tt.fields.A,
				S:        tt.fields.S,
				T1:       tt.fields.T1,
				T2:       tt.fields.T2,
				taux:     tt.fields.taux,
				mu:       tt.fields.mu,
				t:        tt.fields.t,
				IPProof:  tt.fields.IPProof,
			}
			if err := p.Decode(tt.args.r, tt.args.includeCommits); (err != nil) != tt.wantErr {
				t.Errorf("Proof.Decode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProof_Equals(t *testing.T) {
	type fields struct {
		V        []pedersen.Commitment
		Blinders []ristretto.Scalar
		A        ristretto.Point
		S        ristretto.Point
		T1       ristretto.Point
		T2       ristretto.Point
		taux     ristretto.Scalar
		mu       ristretto.Scalar
		t        ristretto.Scalar
		IPProof  *innerproduct.Proof
	}
	type args struct {
		other          Proof
		includeCommits bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proof{
				V:        tt.fields.V,
				Blinders: tt.fields.Blinders,
				A:        tt.fields.A,
				S:        tt.fields.S,
				T1:       tt.fields.T1,
				T2:       tt.fields.T2,
				taux:     tt.fields.taux,
				mu:       tt.fields.mu,
				t:        tt.fields.t,
				IPProof:  tt.fields.IPProof,
			}
			if got := p.Equals(tt.args.other, tt.args.includeCommits); got != tt.want {
				t.Errorf("Proof.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_readerToPoint(t *testing.T) {
	type args struct {
		r io.Reader
		p *ristretto.Point
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := readerToPoint(tt.args.r, tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("readerToPoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_readerToScalar(t *testing.T) {
	type args struct {
		r io.Reader
		s *ristretto.Scalar
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := readerToScalar(tt.args.r, tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("readerToScalar() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_generateProof(t *testing.T) {
	type args struct {
		m int
		t *testing.T
	}
	tests := []struct {
		name string
		args args
		want *Proof
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateProof(tt.args.m, tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateProof() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBenchmarkProve(t *testing.T) {
	type args struct {
		b *testing.B
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BenchmarkProve(tt.args.b)
		})
	}
}

func TestBenchmarkVerify(t *testing.T) {
	type args struct {
		b *testing.B
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BenchmarkVerify(tt.args.b)
		})
	}
}
