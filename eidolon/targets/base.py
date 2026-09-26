"""Execution adaptor interface.

Eidolon's `Execution Adaptor` is the only library-specific part of the design:
it turns an arithmetic expression into concrete FHE API calls, executes them,
and reports back (i) the decrypted result per equivalent form, (ii) the residual
noise, (iii) any crash.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any

import sympy as sp

from ..expr import ExprSpec


@dataclass
class EvalResult:
    """Outcome of executing one test case (one expression, three forms)."""

    #: form name -> decrypted per-slot values (ints).  Missing/None == failed.
    outputs: dict[str, list[int] | None] = field(default_factory=dict)
    #: exact integer baseline for the same slots
    native: list[int] = field(default_factory=list)
    #: OPTIONAL per-form baseline, when the forms do not share one modular
    #: semantics (e.g. a compiler that infers a different output bit width per
    #: form).  The oracle prefers this over `native` when present.
    natives: dict[str, list[int]] = field(default_factory=dict)
    #: residual noise budget of the *worst* form, normalised to [0,1] by eta_0
    noise_ratio: float | None = None
    #: raw residual noise (library units: bits for SEAL)
    noise_raw: float | None = None
    #: set when the target raised / crashed
    error: str | None = None
    crash: bool = False
    crash_kind: str = ""
    #: free-form per-target diagnostics (depths used, api calls, ...)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        """At least one form decrypted to something."""
        return self.error is None and any(v is not None for v in self.outputs.values())

    @property
    def all_failed_to_decrypt(self) -> bool:
        return bool(self.outputs) and all(v is None for v in self.outputs.values())


class Target:
    """Base class.  Subclasses implement `setup` and `evaluate`."""

    name = "abstract"
    #: library plaintext modulus semantics; None for approximate schemes
    plain_modulus: int | None = None
    #: number of SIMD slots a single ciphertext carries
    slots: int = 1
    #: max multiplicative depth the configured parameters can sustain
    max_depth: int = 4
    #: Native adaptors with their own persistent process boundary must not be
    #: forked by Engine for each request; their runner owns crash/timeout logic.
    manages_isolation: bool = False

    def setup(self) -> None:  # pragma: no cover - trivial
        pass

    def fresh_noise(self) -> float:
        """eta_0: residual noise of a freshly encrypted ciphertext."""
        raise NotImplementedError

    def evaluate(
        self,
        spec: ExprSpec,
        xvals: list[int],
        forms: dict[str, sp.Expr],
    ) -> EvalResult:
        raise NotImplementedError

    # -- optional target-specific search axes --------------------------------
    #
    # Eidolon's core expression is intentionally kept scheme-agnostic.  A
    # target may nevertheless need extra, *semantics preserving* case state
    # (for example a BGV parameter set or a common post-expression operator).
    # These hooks keep that state outside ExprSpec, so adding such an axis does
    # not silently change the search space of other libraries.
    def seed_case_states(self) -> list[dict[str, Any]]:
        """States attached to curated seeds; the default is one empty state."""
        return [{}]

    def mutate_case(self, seed: Any, rng: Any, mode: str) -> dict[str, Any]:
        """Return state for the next case.  The default preserves seed state."""
        return {
            "params_id": getattr(seed, "params_id", None),
            "postfix": getattr(seed, "postfix", "identity"),
            "postfix_arg": getattr(seed, "postfix_arg", 0),
            "scale_invariant": getattr(seed, "scale_invariant", False),
        }

    def max_depth_for_case(self, state: dict[str, Any]) -> int:
        """Per-case workload ceiling; targets with one parameter set use max_depth."""
        return self.max_depth

    def make_xvals_for_case(self, rng: Any, slots: int, state: dict[str, Any]) -> list[int] | None:
        """Optional target-specific SIMD input domain.  None keeps Engine's default."""
        return None

    def evaluate_case(
        self,
        spec: ExprSpec,
        xvals: list[int],
        forms: dict[str, sp.Expr],
        state: dict[str, Any],
        *,
        injected_fault: str | None = None,
        fault_forms: tuple[str, ...] = (),
    ) -> EvalResult:
        """Execute one expression plus optional target-specific case state.

        Generic targets deliberately ignore the additional state.  The two
        fault-only keyword arguments are used by target-local oracle gates and
        are never set by production campaigns.
        """
        _ = state, injected_fault, fault_forms
        return self.evaluate(spec, xvals, forms)

    def run_metadata(self) -> dict[str, Any]:
        """Target diagnostics persisted in run.json (empty for generic targets)."""
        return {}

    def close(self) -> None:
        pass

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _err(exc: BaseException) -> str:
        return f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _tb(exc: BaseException) -> str:
        return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
