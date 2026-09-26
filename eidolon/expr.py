"""Arithmetic-expression representation and Equivalence Expression Transformation.

An expression is a univariate integer polynomial in ``x`` with integer
coefficients.  It is *carried* as a factored spec::

    scale * (a_1*x + b_1) * ... * (a_k*x + b_k) + const

which keeps the three mathematically-equivalent structural forms of Eidolon
(Standard / Factored / Horner) cheap to produce and mutate:

  * **Standard**  -- ``expand(spec)``
  * **Factored**  -- the spec kept as a product (no expansion)
  * **Horner**    -- ``horner(expand(spec))``

The polynomial coefficients are also the native baseline: integer arithmetic
in the host language is exact, which is what makes the oracle work without any
external ground truth.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field, replace
from typing import Sequence

import sympy as sp

X = sp.Symbol("x")


@dataclass(frozen=True)
class ExprSpec:
    """`scale * prod(a_i*x + b_i) + const`."""

    factors: tuple[tuple[int, int], ...]
    scale: int = 1
    const: int = 0
    # bookkeeping, not part of the identity
    origin: str = "seed"

    # -- derived symbolic forms ------------------------------------------------
    def factored(self) -> sp.Expr:
        e: sp.Expr = sp.Integer(self.scale)
        for a, b in self.factors:
            e = e * (sp.Integer(a) * X + sp.Integer(b))
        return e + sp.Integer(self.const)

    def standard(self) -> sp.Expr:
        return sp.expand(self.factored())

    def horner(self) -> sp.Expr:
        return sp.horner(self.standard())

    def forms(self) -> dict[str, sp.Expr]:
        """The three structurally-distinct equivalent forms Eidolon compares."""
        return {
            "standard": self.standard(),
            "factored": self.factored(),
            "horner": self.horner(),
        }

    # -- polynomial view -------------------------------------------------------
    def coeffs(self) -> list[int]:
        """Coefficients [c_0, c_1, ...] of the expanded polynomial (exact ints)."""
        poly = sp.Poly(self.standard(), X)
        deg = poly.degree()
        return [int(poly.nth(i)) for i in range(deg + 1)]

    def degree(self) -> int:
        return len(self.coeffs()) - 1

    def __str__(self) -> str:
        parts = [f"{self.scale}"] if self.scale != 1 else []
        for a, b in self.factors:
            parts.append(f"({a}x+{b})")
        s = "*".join(parts) if parts else "1"
        if self.const:
            s += f" + {self.const}" if self.const > 0 else f" - {-self.const}"
        return s

    def canonical(self) -> tuple:
        """Identity of the *mathematical function*, used for corpus dedup."""
        return tuple(self.coeffs())

    def clamped(self, max_depth: int) -> "ExprSpec":
        """Return a valid lower-depth projection of this specification.

        A mutation that crosses a target's depth budget is still useful input:
        dropping the factors that caused the crossing preserves the rest of the
        generated case and lets the fuzzer explore the neighbourhood below the
        boundary.  This is deliberately a structural constraint, not a change
        to the oracle or a rejection-and-random-reseed policy.

        ``ExprSpec`` contains only linear factors, so removing factors is enough
        to reduce its multiplicative degree.  If ``max_depth`` is negative the
        request is invalid; callers should discard that case.
        """
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        factors = list(self.factors)
        candidate = self
        while factors and candidate.degree() > max_depth:
            # Remove the newest factor first.  Keeping the prefix makes the
            # clamp deterministic and retains the mutation's earlier work.
            factors.pop()
            candidate = replace(self, factors=tuple(factors),
                                origin=f"clamp:{self.origin}")
        return candidate


def structure_fingerprint(expr: sp.Expr) -> str:
    """A coarse structural signature, used to reject forms that are not distinct."""
    return sp.srepr(expr)


def distinct_forms(spec: ExprSpec) -> dict[str, sp.Expr]:
    """Forms whose structure actually differs.

    Eidolon's oracle needs structurally *different* execution paths; if (say)
    the factored form expands to exactly the standard tree, comparing them
    proves nothing, so we drop it.
    """
    forms = spec.forms()
    seen: dict[str, str] = {}
    out: dict[str, sp.Expr] = {}
    for name, expr in forms.items():
        fp = structure_fingerprint(expr)
        if fp in seen:
            continue
        seen[fp] = name
        out[name] = expr
    return out


# ---------------------------------------------------------------------------
# native (plaintext) baseline
# ---------------------------------------------------------------------------

def native_eval(coeffs: Sequence[int], xvals: Sequence[int]) -> list[int]:
    """Exact integer evaluation of a polynomial at every slot value.

    Exactness matters: this is the ground truth the FHE result is compared to.
    """
    out = []
    for v in xvals:
        acc = 0
        for c in reversed(coeffs):
            acc = acc * v + c
        out.append(acc)
    return out


def center_mod(v: int, modulus: int) -> int:
    """Symmetric residue in (-modulus/2, modulus/2]."""
    r = v % modulus
    if r > modulus // 2:
        r -= modulus
    return r


def native_eval_mod(coeffs: Sequence[int], xvals: Sequence[int], modulus: int) -> list[int]:
    """Baseline under the target's plaintext-modulus semantics."""
    return [center_mod(v, modulus) for v in native_eval(coeffs, xvals)]


# ---------------------------------------------------------------------------
# random generation (seed corpus)
# ---------------------------------------------------------------------------

def random_spec(
    rng: random.Random,
    n_factors: int | None = None,
    coeff_limit: int = 6,
    const_limit: int = 12,
) -> ExprSpec:
    if n_factors is None:
        n_factors = rng.randint(1, 3)
    factors = []
    for _ in range(n_factors):
        a = rng.choice([1, 1, 1, 2, 3, -1, -2])
        b = rng.randint(-coeff_limit, coeff_limit)
        factors.append((a, b))
    scale = rng.choice([1, 1, 2, 3, -1, -2])
    const = rng.randint(-const_limit, const_limit)
    return ExprSpec(tuple(factors), scale, const, origin="random")
