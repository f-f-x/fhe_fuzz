"""Noise-aware mutators (paper Sec. 4.2, "Noise-Aware Mutation").

Two complementary operators, selected by the residual noise of the previous
execution:

  * **High-Noise Mutator** -- aggressively increases computational complexity so
    the search reaches deeper into the noise-constrained computational space:
    insert a multiplication, add a new factor, magnify coefficients.
  * **Low-Noise Mutator** -- fine-grained edits that explore the *neighbourhood*
    of a seed that already sits at the noise boundary: insert an addition,
    drop a factor (reduce depth), shrink coefficients.

Both operate on the factored spec, so every mutation immediately yields the
three equivalent forms via `ExprSpec.forms()`.
"""
from __future__ import annotations

import random

from .expr import ExprSpec

# Bounds keep a mutated expression inside the region a BFV context can evaluate.
MAX_FACTORS = 5
MAX_COEFF = 200
MAX_CONST = 4096


def high_noise_mutator(spec: ExprSpec, rng: random.Random) -> ExprSpec:
    """Push toward deeper / noisier computations."""
    op = rng.choice(["insert_factor", "square_like", "magnify", "raise_degree"])
    factors = list(spec.factors)
    scale, const = spec.scale, spec.const

    if op == "insert_factor" and len(factors) < MAX_FACTORS:
        a = rng.choice([1, 1, 2, -1])
        b = rng.randint(-8, 8)
        factors.append((a, b))
    elif op == "square_like" and len(factors) < MAX_FACTORS:
        # duplicate an existing factor -> the product gets an extra power,
        # which raises the multiplicative depth of the standard form
        if factors:
            factors.append(rng.choice(factors))
        else:
            factors.append((1, rng.randint(-4, 4)))
    elif op == "magnify":
        if factors:
            i = rng.randrange(len(factors))
            a, b = factors[i]
            k = rng.choice([2, 3, 5, 7])
            a = max(-MAX_COEFF, min(MAX_COEFF, a * k))
            b = max(-MAX_COEFF, min(MAX_COEFF, b * k))
            factors[i] = (a, b)
        scale = max(-MAX_COEFF, min(MAX_COEFF, scale * rng.choice([2, 3, 5])))
    elif op == "raise_degree":
        const = rng.choice([1, -1, 2]) * min(MAX_CONST, max(1, abs(const) * 3 + 7))

    return ExprSpec(tuple(factors), scale, const, origin=f"high:{op}")


def low_noise_mutator(spec: ExprSpec, rng: random.Random) -> ExprSpec:
    """Fine-grained exploration near the noise boundary."""
    op = rng.choice(["insert_addition", "drop_factor", "shrink", "tweak_const"])
    factors = list(spec.factors)
    scale, const = spec.scale, spec.const

    if op == "insert_addition":
        const += rng.choice([1, -1, 2, -2, 3, -3])
    elif op == "drop_factor" and len(factors) > 1:
        factors.pop(rng.randrange(len(factors)))
    elif op == "shrink":
        if factors:
            i = rng.randrange(len(factors))
            a, b = factors[i]
            factors[i] = (_div(a), _div(b))
        scale = _div(scale)
    elif op == "tweak_const":
        const = const // 2 if const else rng.choice([1, -1])

    if not factors:
        factors = [(1, rng.randint(-2, 2))]
    return ExprSpec(tuple(factors), scale, const, origin=f"low:{op}")


def _div(x: int) -> int:
    """Halve toward zero, never to 0 (a zero factor collapses the expression)."""
    if x == 0:
        return 0
    v = int(x / 2)
    return v if v != 0 else (1 if x > 0 else -1)


def mutate(spec: ExprSpec, rng: random.Random, mode: str) -> ExprSpec:
    """mode: 'high' | 'low'."""
    if mode == "low":
        return low_noise_mutator(spec, rng)
    return high_noise_mutator(spec, rng)


def clamp(spec: ExprSpec, max_depth: int) -> ExprSpec:
    """Project an over-depth mutation into the target's legal depth region."""
    return spec.clamped(max_depth)


def simplify(spec: ExprSpec, rng: random.Random) -> ExprSpec:
    """The reduction step used when minimising a confirmed bug (paper: MWE).

    Applies one low-noise edit that is guaranteed to keep the same structural
    family, so a shrink loop can drive a reproducer down to a minimal case.
    """
    factors = list(spec.factors)
    if len(factors) > 1:
        return ExprSpec(tuple(factors[1:]), spec.scale, spec.const, origin="reduce")
    if len(factors) == 1 and factors[0] != (1, 0):
        a, b = factors[0]
        return ExprSpec(((1, b),), spec.scale, spec.const, origin="reduce")
    if spec.const:
        return ExprSpec(spec.factors, spec.scale, 0, origin="reduce")
    if spec.scale not in (0, 1):
        return ExprSpec(spec.factors, 1, spec.const, origin="reduce")
    return spec
