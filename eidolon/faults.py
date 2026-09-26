"""Fault injection: validating the oracle end to end.

A fuzzer that reports "no bugs found" is only trustworthy if we know it *would*
report a bug when one is present.  Each fault below emulates one concrete bug
class from Eidolon's own bug table (Table 1) by corrupting the expression that
the *FHE side* evaluates while the native baseline keeps using the true
polynomial.  The result is a genuine divergence between the homomorphic
evaluation and exact integer arithmetic -- exactly what an implementation bug
produces.

    fault injected  ->  oracle must emit a CONFIRMED correctness bug
                        with a cross-form / uniform deviation signal

These wrappers deliberately do NOT touch the oracle, the corpus or the engine;
they only make the target lie about the computation.
"""
from __future__ import annotations

import os
import signal

import sympy as sp

from .targets.base import EvalResult, Target

X = sp.Symbol("x")


class _FaultedTarget(Target):
    """Delegates to `inner`, but corrupts the FHE-side expression."""

    def __init__(self, inner: Target, transform, fault_name: str, forms=("standard",)):
        self.inner = inner
        self.transform = transform
        self.fault_name = fault_name
        self.forms = set(forms)
        self.name = f"{inner.name}+fault:{fault_name}"
        self.plain_modulus = inner.plain_modulus
        self.slots = inner.slots
        self.max_depth = inner.max_depth
        self.manages_isolation = inner.manages_isolation

    def setup(self):
        self.inner.setup()
        self.plain_modulus = self.inner.plain_modulus
        self.slots = self.inner.slots
        self.max_depth = self.inner.max_depth
        self.manages_isolation = self.inner.manages_isolation

    def fresh_noise(self):
        return self.inner.fresh_noise()

    def evaluate(self, spec, xvals, forms):
        broken = {
            k: (self.transform(v) if k in self.forms else v)
            for k, v in forms.items()
        }
        res = self.inner.evaluate(spec, xvals, broken)
        # Some adaptors (notably the out-of-process Lattigo bridge) lower the
        # carried ExprSpec rather than the SymPy form object.  Preserve the
        # end-to-end fault-injection self-test by corrupting the selected FHE
        # form's first slot after execution; production targets never enter
        # this wrapper.
        if self.inner.name == "lattigo-bgv" or self.fault_name in {
                "ciphertext-serialization", "simd-slot-crosstalk", "tfhe-bootstrap"}:
            for name in self.forms:
                if name in res.outputs and res.outputs[name]:
                    if self.fault_name == "simd-slot-crosstalk":
                        # A slot-local corruption must remain invisible to the
                        # polynomial baseline except at one SIMD coordinate.
                        res.outputs[name][0] += 1
                    elif self.fault_name == "ciphertext-serialization":
                        # Model a round-trip that flips one plaintext residue.
                        res.outputs[name][0] += 1
                    elif self.fault_name == "tfhe-bootstrap":
                        # Bootstrap loses one bit on the selected path.
                        res.outputs[name][0] ^= 1
                    elif self.inner.name == "lattigo-bgv":
                        res.outputs[name][0] += 1
        res.meta["fault"] = self.fault_name
        return res

    def close(self):
        self.inner.close()


class _CrashTarget(Target):
    """Emulates a null-pointer / missing-validation crash (paper CVEs)."""

    def __init__(self, inner: Target, predicate, crash_name: str):
        self.inner = inner
        self.predicate = predicate
        self.crash_name = crash_name
        self.name = f"{inner.name}+fault:{crash_name}"
        self.plain_modulus = inner.plain_modulus
        self.slots = inner.slots
        self.max_depth = inner.max_depth
        self.manages_isolation = inner.manages_isolation

    def setup(self):
        self.inner.setup()
        self.plain_modulus = self.inner.plain_modulus
        self.slots = self.inner.slots
        self.max_depth = self.inner.max_depth
        self.manages_isolation = self.inner.manages_isolation

    def fresh_noise(self):
        return self.inner.fresh_noise()

    def evaluate(self, spec, xvals, forms):
        if self.predicate(spec):
            if self.inner.manages_isolation:
                # A persistent native runner cannot be forked safely. Return
                # the same crash classification directly; real native signals
                # are still isolated by JsonLineRunner itself.
                return EvalResult(crash=True, crash_kind="synthetic-signal-11",
                                  error=f"synthetic {self.crash_name}")
            os.kill(os.getpid(), signal.SIGSEGV)
        return self.inner.evaluate(spec, xvals, forms)

    def close(self):
        self.inner.close()


# ---------------------------------------------------------------------------
# concrete faults, each mapped to a documented bug class
# ---------------------------------------------------------------------------

def fault_square_offbyone(inner: Target) -> Target:
    """x**2 evaluated as x**2 - x -- off-by-one in the exponentiation path.

    Models OpenFHE CVE-2024-50669 ("integer overflow when x^2 equals 2^63 due to
    incorrect comparison operators") and the SEAL BFV square-path bug.
    """
    def t(e):
        return sp.expand(e.subs(X ** 2, X ** 2 - X))
    return _FaultedTarget(inner, t, "square-offbyone")


def fault_drop_constant(inner: Target) -> Target:
    """The additive constant is silently lost during lowering.

    Models parameter/handling bugs where a term is dropped (SEAL BUG#719 class).
    """
    def t(e):
        return sp.expand(e - _min_degree_term(e))
    return _FaultedTarget(inner, t, "drop-constant")


def fault_wrong_modulus(inner: Target) -> Target:
    """Coefficients are reduced with the wrong (halved) modulus.

    Models the plaintext/ciphertext modulus-mismatch bugs that cause silent
    wrong results (paper Bug Study 1, CKKS boundary check).
    """
    def t(e):
        poly = sp.Poly(sp.expand(e), X)
        coeffs = [int(poly.nth(i)) for i in range(poly.degree() + 1)]
        m = inner.plain_modulus
        if m is None:
            # The target has no single plaintext modulus -- a compiler that
            # infers the ring per circuit (Concrete).  Emulate the same defect,
            # "the result ring is half as wide as it should be", by deriving the
            # halved ring from the widest coefficient that actually occurs.
            # Falling back to a hard-coded modulus would silently make this
            # fault a no-op whenever the coefficients are smaller than it.
            widest = max((abs(c) for c in coeffs), default=0)
            m = 2 << max(0, widest.bit_length() - 1)
        new = [c % (m // 2) for c in coeffs]
        out = sp.Integer(0)
        for i, c in enumerate(new):
            out += c * X ** i
        return out
    return _FaultedTarget(inner, t, "wrong-modulus")


def fault_negative_plain(inner: Target) -> Target:
    """Ciphertext x plaintext mishandles negative plaintext.

    Models the SEAL BFV `multiply_plain` bug of Eidolon Fig. 2: the negative
    plaintext's magnitude is used with the wrong sign.
    """
    def t(e):
        poly = sp.Poly(sp.expand(e), X)
        coeffs = [int(poly.nth(i)) for i in range(poly.degree() + 1)]
        # a negative constant term comes out positive in the FHE path
        coeffs = [abs(c) if i == 0 and c < 0 else c for i, c in enumerate(coeffs)]
        out = sp.Integer(0)
        for i, c in enumerate(coeffs):
            out += c * X ** i
        return out
    return _FaultedTarget(inner, t, "negative-plaintext")


def fault_horner_only(inner: Target) -> Target:
    """Only the Horner lowering is wrong (a compiler-rewrite miscompilation).

    This is the case that a naive "compare FHE against native" oracle would keep
    re-reporting as a noise failure; the cross-form signal must catch it.
    """
    def t(e):
        return sp.expand(e + 1)
    return _FaultedTarget(inner, t, "horner-miscompile", forms=("horner",))


def fault_crash_deep(inner: Target) -> Target:
    """Segfault on deep expressions -- the paper's null-pointer CVE class."""
    return _CrashTarget(inner, lambda spec: spec.degree() >= 4, "segv-on-deep")


def fault_ckks_approx_bound(inner: Target) -> Target:
    """Approximate-error fault: one lowering path rounds a boundary term."""
    return _FaultedTarget(inner, lambda e: sp.expand(e + 1),
                          "ckks-approx-bound", forms=("standard",))


def fault_ciphertext_serialization(inner: Target) -> Target:
    """Serialization round-trip corrupts one deterministic residue."""
    return _FaultedTarget(inner, lambda e: e, "ciphertext-serialization",
                          forms=("standard",))


def fault_simd_slot_crosstalk(inner: Target) -> Target:
    """One SIMD slot receives a neighbour's value after an operation."""
    return _FaultedTarget(inner, lambda e: e, "simd-slot-crosstalk",
                          forms=("standard",))


def fault_tfhe_bootstrap(inner: Target) -> Target:
    """Bootstrap output loses one bit on one equivalent circuit."""
    return _FaultedTarget(inner, lambda e: e, "tfhe-bootstrap",
                          forms=("standard",))


FAULTS = {
    "square": fault_square_offbyone,
    "drop-const": fault_drop_constant,
    "wrong-modulus": fault_wrong_modulus,
    "negative-plain": fault_negative_plain,
    "horner": fault_horner_only,
    "crash-deep": fault_crash_deep,
    "ckks-approx": fault_ckks_approx_bound,
    "ciphertext-serialization": fault_ciphertext_serialization,
    "simd-crosstalk": fault_simd_slot_crosstalk,
    "tfhe-bootstrap": fault_tfhe_bootstrap,
}


def _min_degree_term(e: sp.Expr) -> sp.Expr:
    """The additive constant of a polynomial."""
    poly = sp.Poly(sp.expand(e), X)
    return sp.Integer(int(poly.nth(0)))
