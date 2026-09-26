package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	params, err := bgv.NewParametersFromLiteral(bgv.ExampleParameters128BitLogN14LogQP438)
	if err != nil {
		panic(err)
	}

	encoder := bgv.NewEncoder(params)
	pt := bgv.NewPlaintext(params, params.MaxLevel())
	pt.IsBatched = false
	if err = encoder.Encode([]int64{1}, pt); err != nil {
		panic(err)
	}

	test := func(name string, dst ring.Poly) {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					fmt.Printf("%s: panic: %v\n", name, recovered)
				}
			}()
			err := encoder.Decode(pt, dst)
			fmt.Printf("%s: err=%v (dst.N=%d, want=%d)\n", name, err, dst.N(), params.RingT().N())
		}()
	}

	test("empty", ring.Poly{})
	test("short", ring.NewPoly(1, 0))
}
