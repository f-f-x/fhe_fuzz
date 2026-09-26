// Reproducer for the still-open upstream issue #570.  It checks the invariant
// that Scale.BinarySize is at least the number of bytes emitted by
// Scale.MarshalBinary for large exponents.
package main

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func main() {
	s := rlwe.NewScale(new(big.Float).SetPrec(128).SetFloat64(1e100))
	p, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	fmt.Printf("binary_size=%d actual_len=%d\n%s\n", s.BinarySize(), len(p), p)
	if s.BinarySize() < len(p) {
		fmt.Println("REPRODUCED: BinarySize underestimates serialized length")
		return
	}
	fmt.Println("not reproduced")
}
