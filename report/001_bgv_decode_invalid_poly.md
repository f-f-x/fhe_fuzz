### What version of Lattigo are you using?

`main` at `5dbffbdea05394de2ca3a432ed5318aa832e3f40`, with Go 1.25.0 on Linux amd64.

### Does this issue persist with the latest release?

Not applicable to v6.2.0: support for decoding into `ring.Poly` was added after
that tag. The issue reproduces on the current `main`.

### What were you trying to do?

Check how the new BGV `ring.Poly` decode path handles a destination whose ring
degree does not match `params.RingT().N()`.

### What were you expecting to happen?

`Encoder.Decode` should return an error, as `Encoder.Encode` already does for a
`ring.Poly` with an incompatible ring degree.

### What actually happened?

An empty `ring.Poly` panics. A polynomial with `N=1` returns `nil` and silently
copies only one coefficient, although the expected ring degree is 16384.

The `ring.Poly` branch indexes `values.Coeffs[0]` and calls `copy` without first
validating the destination dimension.

### Reproducibility

Save the following as `repro.go` and run it from a checkout at the commit above
with `go run repro.go`:

```go
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
		defer func() {
			if recovered := recover(); recovered != nil {
				fmt.Printf("%s: panic: %v\n", name, recovered)
			}
		}()
		err := encoder.Decode(pt, dst)
		fmt.Printf("%s: err=%v (dst.N=%d, want=%d)\n", name, err, dst.N(), params.RingT().N())
	}

	test("empty", ring.Poly{})
	test("short", ring.NewPoly(1, 0))
}
```

Output:

```text
empty: panic: runtime error: index out of range [0] with length 0
short: err=<nil> (dst.N=1, want=16384)
```
