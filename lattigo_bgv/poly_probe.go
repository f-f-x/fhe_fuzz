// Differential probe for the ring.Poly Encode/Decode API added on upstream
// main. It compares the new path with the documented non-batched []int64 path.
package main

import (
	"fmt"
	"math/rand"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var lit = bgv.ParametersLiteral{
	LogN: 10,
	Q:    []uint64{0x3fffffa8001, 0x1000090001, 0x10000c8001, 0x10000f0001, 0xffff00001},
	P:    []uint64{0x7fffffd8001}, PlaintextModulus: 0x101,
}

func main() {
	p, err := bgv.NewParametersFromLiteral(lit)
	if err != nil {
		panic(err)
	}
	e := bgv.NewEncoder(p)
	r := rand.New(rand.NewSource(20260924))
	for it := 0; it < 1000; it++ {
		poly := ring.NewPoly(p.RingT().N(), p.MaxLevel())
		vals := make([]int64, p.RingT().N())
		for i := range vals {
			v := int64(r.Intn(1<<20)) - (1 << 19)
			vals[i] = v
			poly.Coeffs[0][i] = uint64((v%257 + 257) % 257)
		}
		a := bgv.NewPlaintext(p, p.MaxLevel())
		b := bgv.NewPlaintext(p, p.MaxLevel())
		b.IsBatched = false
		if err = e.Encode(poly, a); err != nil {
			panic(err)
		}
		if err = e.Encode(vals, b); err != nil {
			panic(err)
		}
		if !a.Value.Equal(&b.Value) {
			fmt.Printf("ENCODE_MISMATCH iteration=%d\n", it)
			return
		}
		out := ring.NewPoly(p.RingT().N(), 0)
		if err = e.Decode(a, out); err != nil {
			panic(err)
		}
		for i, got := range out.Coeffs[0] {
			exp := poly.Coeffs[0][i]
			if got != exp {
				fmt.Printf("DECODE_MISMATCH iteration=%d coeff=%d got=%d want=%d\n", it, i, got, exp)
				return
			}
		}
	}
	fmt.Println("OK iterations=1000")
}
