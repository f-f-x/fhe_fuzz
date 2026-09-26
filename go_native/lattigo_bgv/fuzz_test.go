package lattigobgv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const plaintextModulus = int64(257)

var parameterLiteral = bgv.ParametersLiteral{
	LogN: 10,
	Q:    []uint64{0x3fffffa8001, 0x1000090001, 0x10000c8001, 0x10000f0001, 0xffff00001},
	P:    []uint64{0x7fffffd8001}, PlaintextModulus: 0x101,
}

type testContext struct {
	params       bgv.Parameters
	enc          *rlwe.Encryptor
	dec          *rlwe.Decryptor
	eval         *bgv.Evaluator
	kgen         *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	relin        *rlwe.RelinearizationKey
	evalByGalois map[string]*bgv.Evaluator
}

func newTestContext(t testing.TB) *testContext {
	t.Helper()
	params, err := bgv.NewParametersFromLiteral(parameterLiteral)
	if err != nil {
		t.Fatal(err)
	}
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	relin := kgen.GenRelinearizationKeyNew(sk)
	return &testContext{
		params:       params,
		enc:          bgv.NewEncryptor(params, pk),
		dec:          bgv.NewDecryptor(params, sk),
		eval:         bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relin), false),
		kgen:         kgen,
		sk:           sk,
		relin:        relin,
		evalByGalois: make(map[string]*bgv.Evaluator),
	}
}

func (c *testContext) encrypt(t *testing.T, values []int64) *rlwe.Ciphertext {
	pt := bgv.NewPlaintext(c.params, c.params.MaxLevel())
	pt.IsBatched = true
	if err := c.eval.Encode(values, pt); err != nil {
		t.Fatal(err)
	}
	ct, err := c.enc.EncryptNew(pt)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func center(v int64) int64 {
	v %= plaintextModulus
	if v < 0 {
		v += plaintextModulus
	}
	if v > plaintextModulus/2 {
		v -= plaintextModulus
	}
	return v
}

func sameResidue(a, b int64) bool {
	return center(a-b) == 0
}

func valuesFrom(data []byte, n int) []int64 {
	values := make([]int64, n)
	for i := range values {
		if len(data) == 0 {
			break
		}
		values[i] = int64(int(data[i%len(data)])) - 128
	}
	return values
}

// FuzzBGVEncodeDecodeRoundTrip checks the public encoder contract over signed
// boundary values. It is a Go-native crash/assertion target; it complements
// the Python equivalent-expression oracle, which is needed for silent errors.
func FuzzBGVEncodeDecodeRoundTrip(f *testing.F) {
	c := newTestContext(f)
	f.Add([]byte{0, 1, 127, 128, 255})
	f.Add([]byte{128, 127, 1, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			data = []byte{0}
		}
		n := int(data[0]%16) + 1
		values := valuesFrom(data[1:], n)
		ct := c.encrypt(t, values)
		pt := c.dec.DecryptNew(ct)
		got := make([]int64, c.params.MaxSlots())
		if err := c.eval.Decode(pt, got); err != nil {
			t.Fatal(err)
		}
		for i, want := range values {
			if !sameResidue(got[i], want) {
				writeArtifact(t, "encode_decode_mismatch", nil, values)
				t.Fatalf("slot %d: got %d want %d", i, got[i], center(want))
			}
		}
	})
}

// FuzzBGVArithmeticAgainstNative exercises the evaluator with a bounded,
// low-noise scalar path so a silent wrong residue becomes a Go fuzz failure.
func FuzzBGVArithmeticAgainstNative(f *testing.F) {
	c := newTestContext(f)
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add([]byte{255, 0, 127, 128})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			data = []byte{0}
		}
		n := int(data[0]%8) + 1
		values := valuesFrom(data[1:], n)
		add := int64(int(data[0]%7) - 3)
		mul := int64(int(data[len(data)-1]%5) - 2)
		if mul == 0 {
			mul = 1
		}
		ct := c.encrypt(t, values)
		var err error
		ct, err = c.eval.AddNew(ct, add)
		if err != nil {
			t.Fatal(err)
		}
		ct, err = c.eval.MulRelinNew(ct, mul)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]int64, c.params.MaxSlots())
		if err = c.eval.Decode(c.dec.DecryptNew(ct), got); err != nil {
			t.Fatal(err)
		}
		for i, x := range values {
			if !sameResidue(got[i], (x+add)*mul) {
				writeArtifact(t, "arithmetic_mismatch", [][]int64{{mul, add}}, values)
				t.Fatalf("slot %d: got %d want %d", i, got[i], center((x+add)*mul))
			}
		}
	})
}

// FuzzBGVDecodeDestination is opt-in because the current upstream behavior is
// intentionally a known finding: malformed coefficient destinations panic or
// silently accept the wrong dimension. The panic is emitted by Go's fuzzer;
// the JSON artifact makes it replayable by the Python oracle.
func FuzzBGVDecodeDestination(f *testing.F) {
	if os.Getenv("FHE_FUZZ_EXPECT_BUG") != "1" {
		f.Skip("opt-in known upstream finding")
	}
	f.Add([]byte{0})
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, data []byte) {
		c := newTestContext(t)
		pt := bgv.NewPlaintext(c.params, c.params.MaxLevel())
		pt.IsBatched = false
		if err := c.eval.Encode([]int64{1, 2, 3}, pt); err != nil {
			t.Fatal(err)
		}
		var dst ring.Poly
		if len(data) > 0 && data[0]&1 == 1 {
			dst = c.params.RingT().NewPoly()
		}
		if len(data) > 0 && data[0]&2 == 2 {
			dst = ring.NewPoly(1, 0)
		}
		if dst.N() != c.params.RingT().N() {
			writeArtifact(t, "decode_destination", nil, []int64{1, 2, 3})
		}
		if err := c.eval.Decode(pt, dst); err != nil {
			return
		}
		if dst.N() != c.params.RingT().N() {
			t.Fatalf("accepted destination N=%d", dst.N())
		}
	})
}

// Keep the artifact format deliberately identical to the Python adaptor's
// request. A caller can set FHE_FUZZ_ARTIFACT_DIR and attach this JSON to an
// issue or replay it with replay_go_case.py.
func writeArtifact(t *testing.T, name string, factors [][]int64, x []int64) {
	dir := os.Getenv("FHE_FUZZ_ARTIFACT_DIR")
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	payload := map[string]any{"factors": factors, "scale": 1, "const": 0, "x": x,
		"forms": []string{"standard", "factored", "horner"}, "source": name}
	b, _ := json.MarshalIndent(payload, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644)
}
