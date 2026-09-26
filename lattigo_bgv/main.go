// eidolon_bgv is the small, version-pinned execution adaptor used by
// fhe_fuzz. It is deliberately kept outside the Lattigo source tree: the
// caller runs it from a checked-out Lattigo module, so the imports resolve to
// exactly the revision under test.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type request struct {
	Factors [][]int64 `json:"factors"`
	Scale   int64     `json:"scale"`
	Const   int64     `json:"const"`
	X       []int64   `json:"x"`
	// Forms lets the Python oracle execute precisely the independently lowered
	// expressions it is comparing. An empty list keeps the command-line helper
	// convenient and evaluates every form.
	Forms []string `json:"forms,omitempty"`
}

type response struct {
	Outputs      map[string][]int64 `json:"outputs,omitempty"`
	NoiseRaw     float64            `json:"noise_raw,omitempty"`
	NoiseRatio   float64            `json:"noise_ratio"`
	FreshNoise   float64            `json:"fresh_noise,omitempty"`
	NoiseBound   float64            `json:"noise_bound,omitempty"`
	NoiseBudget  float64            `json:"noise_budget,omitempty"`
	Slots        int                `json:"slots,omitempty"`
	PlainModulus uint64             `json:"plain_modulus,omitempty"`
	Meta         map[string]any     `json:"meta,omitempty"`
	Error        string             `json:"error,omitempty"`
	Crash        bool               `json:"crash,omitempty"`
}

// The test parameter set is Lattigo's fast BGV test set. It is intentionally
// small enough for a fuzz campaign, while still exercising SIMD encoding,
// ciphertext-ciphertext multiplication and relinearization.
var parameterLiteral = bgv.ParametersLiteral{
	LogN:             10,
	Q:                []uint64{0x3fffffa8001, 0x1000090001, 0x10000c8001, 0x10000f0001, 0xffff00001},
	P:                []uint64{0x7fffffd8001},
	PlaintextModulus: 0x101,
}

type context struct {
	params bgv.Parameters
	enc    *rlwe.Encryptor
	dec    *rlwe.Decryptor
	eval   *bgv.Evaluator
	eta0   float64
	budget float64
}

func newContext() (*context, error) {
	params, err := bgv.NewParametersFromLiteral(parameterLiteral)
	if err != nil {
		return nil, err
	}
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	relin := kgen.GenRelinearizationKeyNew(sk)
	ctx := &context{
		params: params,
		enc:    bgv.NewEncryptor(params, pk),
		dec:    bgv.NewDecryptor(params, sk),
		eval:   bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relin), false),
	}
	zero, err := ctx.encrypt([]int64{0})
	if err != nil {
		return nil, err
	}
	ctx.eta0, _, _ = rlwe.Norm(zero, ctx.dec)
	// Log2(Q/T) is the approximate usable noise budget. Norm reports log2 of
	// the error standard deviation; the ratio below is a capacity estimate,
	// supplemented by the actual decryption result.
	ctx.budget = params.LogQ() - math.Log2(float64(params.PlaintextModulus()))
	return ctx, nil
}

func (c *context) encrypt(values []int64) (*rlwe.Ciphertext, error) {
	pt := bgv.NewPlaintext(c.params, c.params.MaxLevel())
	// The Python oracle treats x as SIMD slots (one independent polynomial
	// evaluation per slot), so explicitly select BGV's batched encoder. The
	// default plaintext is coefficient-encoded and would make multiplication a
	// polynomial convolution, invalidating the native baseline.
	pt.IsBatched = true
	if err := c.eval.Encode(values, pt); err != nil {
		return nil, err
	}
	return c.enc.EncryptNew(pt)
}

func (c *context) zeroWith(v int64) (*rlwe.Ciphertext, error) {
	ct, err := c.encrypt([]int64{0})
	if err != nil {
		return nil, err
	}
	return c.eval.AddNew(ct, v)
}

func (c *context) multiply(a, b *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return c.eval.MulRelinNew(a, b)
}

func (c *context) multiplyScalar(a *rlwe.Ciphertext, b int64) (*rlwe.Ciphertext, error) {
	return c.eval.MulRelinNew(a, b)
}

func centeredMod(v, modulus int64) int64 {
	v %= modulus
	if v < 0 {
		v += modulus
	}
	if v > modulus/2 {
		v -= modulus
	}
	return v
}

func mulMod(a, b, modulus int64) int64 {
	// All fuzz operands are first reduced modulo T (257), so this product is
	// deliberately tiny and cannot overflow. Keeping every intermediate in the
	// plaintext ring also makes the native model agree with FHE semantics.
	return centeredMod(centeredMod(a, modulus)*centeredMod(b, modulus), modulus)
}

func coefficients(r request, modulus int64) []int64 {
	coeff := []int64{centeredMod(r.Scale, modulus)}
	for _, factor := range r.Factors {
		if len(factor) != 2 {
			continue
		}
		a, b := centeredMod(factor[0], modulus), centeredMod(factor[1], modulus)
		next := make([]int64, len(coeff)+1)
		for i, v := range coeff {
			next[i] = centeredMod(next[i]+mulMod(v, b, modulus), modulus)
			next[i+1] = centeredMod(next[i+1]+mulMod(v, a, modulus), modulus)
		}
		coeff = next
	}
	coeff[0] = centeredMod(coeff[0]+r.Const, modulus)
	return coeff
}

func expectedValues(r request, modulus int64, slots int) []int64 {
	coeff := coefficients(r, modulus)
	values := make([]int64, 0)
	for slot := 0; slot < slots; slot++ {
		var x int64
		if slot < len(r.X) {
			x = r.X[slot]
		}
		acc := int64(0)
		for i := len(coeff) - 1; i >= 0; i-- {
			acc = centeredMod(mulMod(acc, x, modulus)+coeff[i], modulus)
		}
		values = append(values, acc)
	}
	return values
}

func (c *context) standard(r request, x *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	coeff := coefficients(r, int64(c.params.PlaintextModulus()))
	acc, err := c.zeroWith(coeff[0])
	if err != nil {
		return nil, err
	}
	pow := x
	for i := 1; i < len(coeff); i++ {
		term, e := c.multiplyScalar(pow, coeff[i])
		if e != nil {
			return nil, e
		}
		acc, e = c.eval.AddNew(acc, term)
		if e != nil {
			return nil, e
		}
		if i+1 < len(coeff) {
			pow, e = c.multiply(pow, x)
			if e != nil {
				return nil, e
			}
		}
	}
	return acc, nil
}

func (c *context) factored(r request, x *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	modulus := int64(c.params.PlaintextModulus())
	acc, err := c.zeroWith(centeredMod(r.Scale, modulus))
	if err != nil {
		return nil, err
	}
	for _, factor := range r.Factors {
		if len(factor) != 2 {
			return nil, fmt.Errorf("factor must have two coefficients")
		}
		term, e := c.multiplyScalar(x, centeredMod(factor[0], modulus))
		if e != nil {
			return nil, e
		}
		term, e = c.eval.AddNew(term, centeredMod(factor[1], modulus))
		if e != nil {
			return nil, e
		}
		acc, e = c.multiply(acc, term)
		if e != nil {
			return nil, e
		}
	}
	return c.eval.AddNew(acc, centeredMod(r.Const, modulus))
}

func (c *context) horner(r request, x *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	coeff := coefficients(r, int64(c.params.PlaintextModulus()))
	acc, err := c.zeroWith(coeff[len(coeff)-1])
	if err != nil {
		return nil, err
	}
	for i := len(coeff) - 2; i >= 0; i-- {
		acc, err = c.multiply(acc, x)
		if err != nil {
			return nil, err
		}
		acc, err = c.eval.AddNew(acc, coeff[i])
		if err != nil {
			return nil, err
		}
	}
	return acc, nil
}

func (c *context) decrypt(ct *rlwe.Ciphertext, expected []int64, outputN int) ([]int64, float64, error) {
	// This follows the Lattigo BGV test suite's noise measurement: remove the
	// expected plaintext first. Norm(ct) by itself includes the scaled message
	// and is therefore not a residual-noise metric.
	ptExpected := bgv.NewPlaintext(c.params, ct.Level())
	ptExpected.MetaData = ct.MetaData
	// Keep these fields explicit: evaluator operations may return a fresh
	// ciphertext metadata object, while NewPlaintext starts with an empty
	// plaintext metadata value.
	ptExpected.IsBatched = true
	ptExpected.Scale = ct.Scale
	if err := c.eval.Encode(expected, ptExpected); err != nil {
		return nil, 0, err
	}
	residual, err := c.eval.SubNew(ct, ptExpected)
	if err != nil {
		return nil, 0, err
	}
	std, min, max := rlwe.Norm(residual, c.dec)
	pt := c.dec.DecryptNew(ct)
	decoded := make([]int64, c.params.MaxSlots())
	if err := c.eval.Decode(pt, decoded); err != nil {
		return nil, std, err
	}
	if outputN > len(decoded) {
		outputN = len(decoded)
	}
	_ = min
	_ = max
	return decoded[:outputN], std, nil
}

func wants(requested []string, name string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, candidate := range requested {
		if candidate == name {
			return true
		}
	}
	return false
}

func (c *context) run(r request) (resp response) {
	resp.Outputs = make(map[string][]int64)
	resp.Slots = c.params.MaxSlots()
	resp.PlainModulus = c.params.PlaintextModulus()
	resp.FreshNoise = c.eta0
	resp.NoiseBudget = c.budget
	resp.NoiseBound = c.params.NoiseBound()
	defer func() {
		if v := recover(); v != nil {
			resp.Crash = true
			resp.Error = fmt.Sprintf("panic: %v", v)
		}
	}()
	forms := []struct {
		name string
		fn   func(*rlwe.Ciphertext) (*rlwe.Ciphertext, error)
	}{
		{"standard", func(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) { return c.standard(r, ct) }},
		{"factored", func(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) { return c.factored(r, ct) }},
		{"horner", func(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) { return c.horner(r, ct) }},
	}
	expected := expectedValues(r, int64(c.params.PlaintextModulus()), c.params.MaxSlots())
	var worst float64 = -math.MaxFloat64
	for _, form := range forms {
		if !wants(r.Forms, form.name) {
			continue
		}
		ct, e := c.encrypt(r.X)
		if e != nil {
			resp.Meta = map[string]any{"encrypt_error": e.Error()}
			continue
		}
		ct, e = form.fn(ct)
		if e != nil {
			if resp.Meta == nil {
				resp.Meta = map[string]any{}
			}
			resp.Meta[form.name+"_error"] = e.Error()
			continue
		}
		out, raw, e := c.decrypt(ct, expected, len(r.X))
		if raw > worst {
			worst = raw
		}
		if e != nil {
			if resp.Meta == nil {
				resp.Meta = map[string]any{}
			}
			resp.Meta[form.name+"_error"] = e.Error()
			continue
		}
		resp.Outputs[form.name] = out
	}
	if worst > -math.MaxFloat64 {
		resp.NoiseRaw = worst
		// eta0 is the residual noise of a fresh encryption. Remaining capacity is
		// normalized against the fresh remaining capacity, not the full Q/T span.
		freshRemaining := c.budget - c.eta0
		resp.NoiseRatio = (c.budget - worst) / freshRemaining
		if resp.NoiseRatio < 0 {
			resp.NoiseRatio = 0
		}
		if resp.NoiseRatio > 1 {
			resp.NoiseRatio = 1
		}
	}
	return resp
}

func main() {
	ctx, err := newContext()
	if err != nil {
		panic(err)
	}
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		var req request
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			_ = json.NewEncoder(out).Encode(response{Error: err.Error()})
			continue
		}
		_ = json.NewEncoder(out).Encode(ctx.run(req))
		_ = out.Flush()
	}
}
