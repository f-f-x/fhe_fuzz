"""Seed corpus with noise-driven prioritisation (paper Sec. 4.2).

The guiding principle in the paper: expressions that execute *without* noise
overflow, and that consume either a very large or a very small share of the
noise budget, are the valuable ones -- they sit at the boundaries and in the
sparse regions of the computational space.  Everything else is demoted.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from .expr import ExprSpec, random_spec

# Seeds lifted from the *usage patterns* of the target libraries: the kind of
# arithmetic that SEAL's own examples / unit tests exercise (cf. paper Sec. 4.2,
# "valid arithmetic sequences extracted from the official unit tests").
CURATED_SEEDS: list[ExprSpec] = [
    ExprSpec(((3, 2),), 1, 0, origin="seed"),            # 3x + 2
    ExprSpec(((1, 1),), 1, 0, origin="seed"),            # x + 1
    ExprSpec(((1, 0),), 1, 0, origin="seed"),            # x
    ExprSpec(((1, 1),), 1, 1, origin="seed"),            # x + 1 + 1
    ExprSpec(((1, 1), (1, 1)), 1, 0, origin="seed"),     # (x+1)^2
    ExprSpec(((1, 1), (1, -1)), 1, 0, origin="seed"),    # x^2 - 1
    ExprSpec(((1, 2), (1, 3)), 1, 1, origin="seed"),     # (x+2)(x+3) + 1
    ExprSpec(((1, 0), (1, 4)), 1, 0, origin="seed"),     # x(x+4)
    ExprSpec(((2, 1), (1, -2), (1, 3)), 1, -5, origin="seed"),
    ExprSpec(((1, -1), (1, 1), (1, 2)), 3, 7, origin="seed"),
    ExprSpec(((1, 0),), 4, 1, origin="seed"),            # 4x + 1
    ExprSpec(((1, 3), (1, 3)), -1, 2, origin="seed"),    # -(x+3)^2 + 2
]


@dataclass
class Seed:
    spec: ExprSpec
    # Extra FHE input axes deliberately live on a seed, rather than ExprSpec:
    # they configure how the same mathematical polynomial is executed.
    params_id: str | None = None
    postfix: str = "identity"
    postfix_arg: int = 0
    scale_invariant: bool = False
    priority: float = 1.0
    hits: int = 0
    best_noise_ratio: float | None = None
    last_noise_ratio: float | None = None
    tags: set[str] = field(default_factory=set)

    def to_json(self) -> dict:
        return {
            "expr": str(self.spec),
            "coeffs": self.spec.coeffs(),
            "origin": self.spec.origin,
            "params_id": self.params_id,
            "postfix": self.postfix,
            "postfix_arg": self.postfix_arg,
            "scale_invariant": self.scale_invariant,
            "priority": round(self.priority, 4),
            "hits": self.hits,
            "best_noise_ratio": self.best_noise_ratio,
            "last_noise_ratio": self.last_noise_ratio,
            "tags": sorted(self.tags),
        }


class Corpus:
    """Evolving set of seeds, keyed by the mathematical function they compute."""

    def __init__(self, rng: random.Random, extra_seeds: list[ExprSpec] | None = None,
                 case_states: list[dict] | None = None):
        self.rng = rng
        self._seeds: dict[tuple, Seed] = {}
        states = case_states or [{}]
        for spec in CURATED_SEEDS + (extra_seeds or []):
            for state in states:
                self.add(spec, **state)

    # -- container protocol ----------------------------------------------------
    def __len__(self) -> int:
        return len(self._seeds)

    def __iter__(self):
        return iter(self._seeds.values())

    def add(self, spec: ExprSpec, priority: float = 1.0, tags: set[str] | None = None,
            *, params_id: str | None = None, postfix: str = "identity",
            postfix_arg: int = 0, scale_invariant: bool = False) -> Seed:
        key = (spec.canonical(), params_id, postfix, int(postfix_arg), bool(scale_invariant))
        s = self._seeds.get(key)
        if s is None:
            s = Seed(spec, params_id, postfix, int(postfix_arg), bool(scale_invariant),
                     priority, tags=set(tags or ()))
            self._seeds[key] = s
        else:
            s.priority = max(s.priority, priority)
            s.tags |= set(tags or ())
        return s

    # -- selection -------------------------------------------------------------
    def select(self) -> Seed:
        """Priority-weighted pick; every seed keeps a non-zero chance."""
        items = list(self._seeds.values())
        weights = [max(0.01, s.priority) for s in items]
        return self.rng.choices(items, weights=weights, k=1)[0]

    def random_new(self, coeff_limit: int = 6) -> Seed:
        return self.add(random_spec(self.rng, coeff_limit=coeff_limit), priority=1.0,
                        tags={"random"})

    # -- feedback --------------------------------------------------------------
    def reward(self, spec: ExprSpec, noise_ratio: float, tau_low: float, tau_high: float,
               max_priority: float = 64.0, **state) -> str:
        """Apply the paper's noise-handler policy.  Returns the verdict name."""
        s = self.add(spec, **state)
        s.last_noise_ratio = noise_ratio
        if s.best_noise_ratio is None or noise_ratio < s.best_noise_ratio:
            s.best_noise_ratio = noise_ratio

        if noise_ratio < tau_low:
            # Low-Noise Handler: pushed the computation to its limit -> high value
            s.priority = min(max_priority, s.priority * 4.0)
            s.tags.add("boundary")
            return "low-noise"
        if noise_ratio < tau_high:
            s.priority = min(max_priority, s.priority * 1.5)
            return "mid-noise"
        # High-Noise Handler: too simple, demote
        s.priority = max(0.05, s.priority * 0.5)
        s.tags.add("shallow")
        return "high-noise"

    def penalise(self, spec: ExprSpec, factor: float = 0.25, **state) -> None:
        """Noise overflow: the expression is not a useful starting point."""
        s = self.add(spec, **state)
        s.priority = max(0.02, s.priority * factor)

    def mark_calibrated_boundaries(self, tau_low: float) -> int:
        """Tag observed seeds at/below a calibrated low-noise quantile.

        Calibration is an observation pass, so it must not rewrite the oracle
        or retroactively change verdicts.  This only annotates the corpus for
        the next campaign and makes the boundary count visible in ``run.json``.
        """
        marked = 0
        for seed in self._seeds.values():
            if (seed.last_noise_ratio is not None
                    and seed.last_noise_ratio <= tau_low):
                if "boundary" not in seed.tags:
                    marked += 1
                seed.tags.add("boundary")
        return marked

    def prune(self, max_size: int) -> int:
        """Bound a long-running corpus without discarding curated entry points.

        Mature coverage fuzzers keep a bounded, interesting corpus.  Here the
        persistent seeds are the library-derived examples; all other entries
        compete on noise-boundary priority and lack of recent use.
        """
        if max_size <= 0 or len(self._seeds) <= max_size:
            return 0
        curated = [s for s in self._seeds.values()
                   if s.spec.origin == "seed" or s.spec.origin.startswith("lattigo:")]
        other = [s for s in self._seeds.values() if s not in curated]
        keep_n = max(0, max_size - len(curated))
        other.sort(key=lambda s: (s.priority, -s.hits), reverse=True)
        kept = curated + other[:keep_n]
        removed = len(self._seeds) - len(kept)
        self._seeds = {
            (s.spec.canonical(), s.params_id, s.postfix, s.postfix_arg,
             s.scale_invariant): s
            for s in kept
        }
        return removed

    # -- persistence -----------------------------------------------------------
    def dump(self, path: str | Path) -> None:
        rows = sorted((s.to_json() for s in self._seeds.values()),
                      key=lambda r: -r["priority"])
        Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def stats(self) -> dict:
        if not self._seeds:
            return {}
        prios = [s.priority for s in self._seeds.values()]
        boundary = sum(1 for s in self._seeds.values() if "boundary" in s.tags)
        return {
            "seeds": len(self._seeds),
            "max_priority": round(max(prios), 3),
            "boundary_seeds": boundary,
        }
