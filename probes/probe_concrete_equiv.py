"""Probe: Equivalence Expression Transformation on Zama Concrete (concrete.fhe).

Compiles Standard / Factored / Horner forms of the same integer polynomial as
three independent circuits and compares their decrypted outputs against exact
native integer arithmetic.  A disagreement between equivalent forms is a
compiler-level correctness signal (miscompilation), exactly the class of bug
Eidolon's oracle is meant to surface.

This is a *probe*: it reports raw discrepancies.  Classifying them as genuine
bugs (vs. unsupported-input rejection) is the job of the oracle in
`eidolon/oracle.py`.
"""
import itertools
import sys
import time

import numpy as np
import sympy as sp

from concrete import fhe

X = sp.Symbol("x")


def bits_for(lo: int, hi: int) -> int:
    n = max(abs(lo), abs(hi))
    return max(1, int(n).bit_length() + 1)


def build_forms(poly: sp.Expr):
    return {
        "standard": sp.expand(poly),
        "horner": sp.horner(sp.expand(poly)),
    }


def poly_fn(expr: sp.Expr):
    """A python function evaluating `expr` with concrete-supported int ops.

    No `int()` / no builtins: the argument may be a concrete `Tracer`, and the
    body must stay inside the traced operator set.
    """
    src = sp.printing.pycode(sp.expand(expr))
    code = compile(src, "<poly>", "eval")

    def f(x):
        return eval(code, {"__builtins__": {}}, {"x": x})  # noqa: S307

    return f


def native_int(expr: sp.Expr, xv: int) -> int:
    return int(sp.expand(expr).subs(X, xv))


def run_case(name: str, poly: sp.Expr, xs: list[int]):
    print(f"\n=== {name}: {sp.expand(poly)} ===")
    lo, hi = min(xs), max(xs)
    # widen the range so intermediate terms fit the inferred bit width
    span = max(abs(lo), abs(hi), 1)
    bits = bits_for(-span, span)
    x_lo, x_hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    inputset = [(np.int64(v),) for v in range(x_lo, min(x_hi, x_lo + 8) + 1)]

    results = {}
    for fname, fexpr in build_forms(poly).items():
        fn = poly_fn(fexpr)
        try:
            t0 = time.time()
            c = fhe.compiler({"x": "encrypted"})(fn)
            circuit = c.compile(inputset)
            dt = time.time() - t0
        except Exception as e:  # compilation refused
            print(f"  [{fname}] COMPILE-FAIL {type(e).__name__}: {str(e)[:140]}")
            continue
        row = []
        for xv in xs:
            xv = int(np.clip(xv, x_lo, x_hi))
            try:
                got = int(circuit.encrypt_run_decrypt(np.int64(xv)))
            except Exception as e:
                got = f"ERR:{type(e).__name__}"
            row.append(got)
        results[fname] = row
        native = [native_int(poly, int(np.clip(v, x_lo, x_hi))) for v in xs]
        bad = [(int(np.clip(xs[i], x_lo, x_hi)), r, native[i])
               for i, r in enumerate(row) if r != native[i]]
        print(f"  [{fname}] compile {dt:5.1f}s  mismatches vs native: {len(bad)}")
        for xv, r, e in bad[:6]:
            print(f"        x={xv:6d}  fhe={r}  native={e}")

    if len(results) > 1:
        names = list(results)
        dis = 0
        for i in range(len(xs)):
            vals = {n: results[n][i] for n in names}
            if len(set(map(str, vals.values()))) > 1:
                if dis < 6:
                    print(f"        FORM-DISAGREEMENT at x={xs[i]}: {vals}")
                dis += 1
        print(f"  cross-form disagreements: {dis}")
    return results


def main():
    poly_sq = (3 * X + 2) ** 2
    cases = [
        ("square_of_linear", poly_sq),
        ("cubic", (X + 1) * (X - 2) * (2 * X + 3)),
        ("quartic", (X + 1) ** 2 * (X - 1) ** 2),
        ("poly6", (X + 1) * (X + 2) * (X + 3) * (2 * X - 1) * (X - 3)),
    ]
    xs = list(range(0, 5)) + [-1, -2, 3]
    for name, poly in cases:
        try:
            run_case(name, poly, xs)
        except Exception as e:
            print(f"\n=== {name} === HARNESS ERROR {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
