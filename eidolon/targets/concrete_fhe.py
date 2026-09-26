"""Execution adaptor for Zama Concrete (`concrete.fhe`).

A different flavour of the same oracle.  Concrete is an FHE *compiler*: it lifts
a Python function to MLIR, runs an optimizer over it (algebraic simplification,
table-lookup conversion, parameter selection), and emits a circuit.  All three
equivalent forms therefore get compiled by the *same optimizer* down different
rewrite paths -- so a disagreement between them is a compiler-level correctness
signal (a miscompilation), which is precisely the bug class the paper's oracle
surfaces and which coverage-guided fuzzers structurally cannot see.

Semantics note: Concrete's integer types are modular (`intN`/`uintN`) and the
*width* of the output type is inferred by the compiler from the traced value
ranges.  Two equivalent forms of the same polynomial can therefore be compiled
to different declared widths (`uint7` vs `int7`).  Comparing a form's output
against one global "plaintext modulus" would manufacture mismatches that are
pure harness artefacts -- a lesson learned the hard way on
``-1*(1x+3)*(1x+3)+1``, where four slots "disagreed" with a hand-written
modulus while agreeing exactly with the circuit's own semantics.  The baseline
is therefore derived **per form**, from the declared output dtype:

    signed   intN  ->  value reduced into [-2**(N-1), 2**(N-1))
    unsigned uintN ->  value reduced into [0, 2**N)

and both the FHE output and the exact result go through the same reduction, so
the comparison happens inside the ring the circuit actually promises.

Known limitation (documented, not fixed): if a miscompilation also *widens* the
inferred output type, the wider baseline can absorb the error.  That direction
is not caught by the per-form baseline; it is caught only when the widened form
also fails to match its own ring.
"""
from __future__ import annotations

import numpy as np
import sympy as sp

from ..expr import ExprSpec, center_mod, native_eval
from .base import EvalResult, Target

X = sp.Symbol("x")


class ConcreteTarget(Target):
    name = "concrete"

    def __init__(self, bits: int = 8, slots: int = 16, exactness: str | None = None):
        from concrete import fhe  # noqa: PLC0415

        self.fhe = fhe
        self.bits = bits
        self.slots = slots
        # Concrete has no single plaintext modulus: the ring is chosen per
        # circuit by the compiler.  Leaving this None also tells the engine not
        # to synthesise "near the plaintext modulus" slot values, which would be
        # meaningless here (and were the source of a former false positive).
        self.plain_modulus = None
        self.max_depth = 12
        self._cache: dict[str, object] = {}
        self._compile_failures = 0
        self._exactness = exactness

    # -- lifecycle ------------------------------------------------------------
    def setup(self) -> None:
        pass

    def fresh_noise(self) -> float:
        """Concrete has no noise-budget read-out.

        Per the paper (Sec. 5, "Noise Monitor"): for a library without a direct
        noise-querying interface, fall back to *correctness-guided inference* --
        i.e. the success/failure of a test decryption stands in for the noise
        level.  We return a constant scale and let the engine's correctness
        signal drive the search.
        """
        return 1.0

    def close(self) -> None:
        self._cache.clear()

    # -- compilation ----------------------------------------------------------
    def _pyfn(self, expr: sp.Expr):
        src = sp.printing.pycode(sp.expand(expr))
        code = compile(src, "<poly>", "eval")

        def f(x):
            return eval(code, {"__builtins__": {}}, {"x": x})  # noqa: S307

        return f

    def _circuit(self, name: str, expr: sp.Expr, probe: list[int]):
        """Compile (and memoise) a circuit for one form of one expression.

        **The inputset must be the probe itself.**  Concrete infers the input
        *domain* (and hence the input dtype) by taking the min/max of the
        inputset, so any value we later feed must be inside that span.  An
        earlier version built a fixed vector `[lo, -1, 0, 1, hi, ...]` truncated
        to `slots` entries -- with `slots=4` the truncation silently dropped
        `hi`, the circuit was compiled for a domain that excluded the largest
        probe value, and feeding that value back produced a garbage decryption
        that looked exactly like a miscompilation.  Deriving the inputset from
        the probe makes the declared domain cover the evaluated values by
        construction, whatever `slots` and the probe happen to be.
        """
        key = f"{name}|{sp.srepr(expr)}|{probe}"
        if key in self._cache:
            return self._cache[key]

        inputset = [np.array(probe, dtype=np.int64)]

        compiler = self.fhe.compiler({"x": "encrypted"})(self._pyfn(expr))
        circuit = compiler.compile(inputset)
        self._cache[key] = circuit
        return circuit

    @staticmethod
    def _out_width(circuit) -> tuple[int, bool]:
        """`(bit_width, is_signed)` of the circuit's first output.

        This is the compiler's *declared* result type, inferred from the traced
        ranges.  It is the only sound choice of modular semantics for comparing
        a decrypted result against exact arithmetic.
        """
        node = next(iter(circuit.graph.output_nodes.values()))
        dtype = node.output.dtype
        return int(dtype.bit_width), bool(dtype.is_signed)

    @staticmethod
    def _reduce(v: int, width: int, signed: bool) -> int:
        """The one reduction applied to *both* sides of the comparison."""
        if signed:
            return center_mod(v, 1 << width)
        return v % (1 << width)

    # -- evaluate -------------------------------------------------------------
    def evaluate(self, spec: ExprSpec, xvals: list[int], forms: dict[str, sp.Expr]) -> EvalResult:
        res = EvalResult()
        coeffs = spec.coeffs()
        n = min(self.slots, len(xvals))
        probe = list(xvals[:n])

        exact = native_eval(coeffs, probe)
        # Fallback baseline, used only if a form's dtype turns out unreadable.
        res.native = [center_mod(v, 1 << self.bits) for v in exact]

        try:
            for fname, fexpr in forms.items():
                try:
                    circuit = self._circuit(fname, fexpr, probe)
                except Exception as e:  # noqa: BLE001
                    self._compile_failures += 1
                    res.outputs[fname] = None
                    res.meta.setdefault("compile_errors", {})[fname] = \
                        f"{type(e).__name__}: {str(e)[:200]}"
                    continue
                # Concrete infers each circuit's integer bit width from the
                # traced ranges, and different equivalent forms can be inferred
                # differently (or be assigned a different rounding strategy).
                # Reducing the baseline with the form's OWN output width is what
                # keeps this comparison honest -- using one global modulus would
                # manufacture mismatches that are pure harness artefacts.
                width, signed = self._out_width(circuit)
                res.natives[fname] = [self._reduce(v, width, signed) for v in exact]
                res.meta.setdefault("out_dtypes", {})[fname] = \
                    f"{'int' if signed else 'uint'}{width}"
                try:
                    out = circuit.encrypt_run_decrypt(np.array(probe, dtype=np.int64))
                    res.outputs[fname] = [
                        self._reduce(int(v), width, signed) for v in np.atleast_1d(out)
                    ]
                except Exception as e:  # noqa: BLE001
                    res.outputs[fname] = None
                    res.meta.setdefault("run_errors", {})[fname] = \
                        f"{type(e).__name__}: {str(e)[:200]}"
            res.meta["compile_failures"] = self._compile_failures
            ok = sum(1 for v in res.outputs.values() if v is not None)
            res.noise_ratio = ok / max(1, len(forms))
        except Exception as e:  # noqa: BLE001
            res.error = self._err(e)
            res.crash = True
            res.crash_kind = type(e).__name__
            res.meta["traceback"] = self._tb(e)
        return res
