# Lattigo latest-main regression: `Scale.BinarySize` underestimates serialized size

## Status

Reproduced on upstream `main` at commit
`5dbffbdea05394de2ca3a432ed5318aa832e3f40` (2026-05-07), with Go 1.25.0.
This is not a new issue: it matches the existing upstream report
[#570](https://github.com/tuneinsight/lattigo/issues/570), so a duplicate issue
must not be opened.

## Reproduction

```bash
cd /home/ffx/fuzz-lab2/.work/lattigo
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go run \
  /home/ffx/fuzz-lab2/fhe_fuzz/lattigo_bgv/scale_probe.go
```

Observed:

```text
binary_size=111 actual_len=112
{"Value":"1.000000000000000015902891109759918046836e+100","Mod":"0.000000000000000000000000000000000000000e+00"}
REPRODUCED: BinarySize underestimates serialized length
```

The invariant violated is `Scale.BinarySize() >= len(Scale.MarshalBinary())`.
The larger ciphertext/serialization failure described in #570 is therefore
still present in this exact checkout and should be tracked there.

## Fuzz harness validation

The Lattigo BGV adaptor was run for 300 bounded-depth iterations (seed
`20260924`, 16 slots, three re-executions). It produced 231 clean executions,
69 expected noise-overflow skips, and no unconfirmed/confirmed library bug.
The same run with the harness's `drop-const` fault injection produced 64
confirmed cross-form divergences, proving the oracle and reproducer path are
active. Those injected results are not Lattigo findings and must not be filed.
