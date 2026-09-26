"""Lattigo v6 BGV execution adaptor.

The Go helper in ``fhe_fuzz/lattigo_bgv/main.go`` is built against the exact
Lattigo checkout selected for a campaign.  Keeping the library call boundary
in Go avoids binding-version drift while the Python side remains the
library-agnostic Eidolon driver.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..expr import ExprSpec, center_mod, native_eval
from ..runner import JsonLineRunner, RunnerFailure
from .base import EvalResult, Target


class LattigoBGVTarget(Target):
    name = "lattigo-bgv"
    manages_isolation = True

    def __init__(self, *, lattigo_root: str | None = None,
                 go_bin: str | None = None, slots: int | None = None):
        here = Path(__file__).resolve().parents[2]
        self.source = here / "lattigo_bgv" / "main.go"
        default_root = os.environ.get("LATTIGO_ROOT")
        self.lattigo_root = Path(lattigo_root or default_root or
                                 "/home/ffx/fuzz-lab2/.work/lattigo").resolve()
        self.go = go_bin or os.environ.get("GO", "go")
        self.binary = self.lattigo_root.parent / "eidolon_bgv"
        self.plain_modulus = 257
        self.slots = slots or 128
        # This is a workload ceiling, not a substitute for noise measurement.
        # The helper reports the residual noise after subtracting the expected
        # plaintext, so the generic oracle can classify budget exhaustion.
        self.max_depth = 5
        self.eta0 = 1.0
        self.runner: JsonLineRunner | None = None
        # Arithmetic projections of the official schemes/bgv tests: batched
        # signed values, coefficient/constant edge cases, square and cubic
        # evaluator paths, and negative/scalar plaintext handling.  Encoding
        # type/length errors and rotations have dedicated Go probes because
        # they are not expressible as a univariate polynomial.
        self.seed_specs = [
            ExprSpec(((1, 0),), 1, 0, origin="lattigo:Encoder/Int/Batched"),
            ExprSpec(((1, 1),), 1, 0, origin="lattigo:Add/Const"),
            ExprSpec(((1, -1), (1, 1)), 1, 0, origin="lattigo:Evaluator/Square"),
            ExprSpec(((1, 0), (1, 0), (1, 0)), 1, 0,
                     origin="lattigo:Evaluator/MulRelin"),
            ExprSpec(((2, 1), (3, -2)), 1, 7,
                     origin="lattigo:Evaluator/MulThenAdd"),
            ExprSpec(((1, 0),), -1, -1, origin="lattigo:NegativePlaintext"),
            ExprSpec(((0, 1),), 1, 0, origin="lattigo:ScalarZero"),
            ExprSpec(((257, 0),), 1, 0, origin="lattigo:PlaintextModulus"),
            ExprSpec(((128, 127),), 1, -128, origin="lattigo:SignedBoundary"),
            ExprSpec(((1, 256),), 1, -257, origin="lattigo:ModulusBoundary"),
            ExprSpec(((2, 3), (2, -3)), -1, 1,
                     origin="lattigo:SignedMul"),
            ExprSpec(((1, 1), (1, 1), (1, 1)), 3, -5,
                     origin="lattigo:Cubic"),
        ]

    def setup(self) -> None:
        if not self.source.is_file():
            raise FileNotFoundError(self.source)
        if not (self.lattigo_root / "go.mod").is_file():
            raise FileNotFoundError(f"not a Lattigo checkout: {self.lattigo_root}")
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [self.go, "build", "-o", str(self.binary), str(self.source)],
            cwd=self.lattigo_root, check=True, text=True,
            capture_output=True,
            env={**os.environ, "GOTOOLCHAIN": "local"},
        )
        self.runner = JsonLineRunner(
            [str(self.binary)], cwd=str(self.lattigo_root),
            env={**os.environ, "GOTOOLCHAIN": "local"}, timeout=45.0)
        self.runner.start()
        self.eta0 = self.fresh_noise()

    def fresh_noise(self) -> float:
        # The helper reports a normalized residual-noise ratio.  A freshly
        # encrypted ciphertext is the reference point used by Eidolon.
        return 1.0

    def close(self) -> None:
        if self.runner:
            self.runner.close()
            self.runner = None

    def evaluate(self, spec: ExprSpec, xvals: list[int], forms) -> EvalResult:
        res = EvalResult()
        res.native = [center_mod(v, self.plain_modulus)
                      for v in native_eval(spec.coeffs(), xvals)]
        if spec.degree() > self.max_depth:
            res.noise_ratio = 0.0
            res.meta = {"skipped": "degree exceeds target workload ceiling",
                        "degree": spec.degree(), "max_depth": self.max_depth}
            return res
        req = {
            "factors": [[int(a), int(b)] for a, b in spec.factors],
            "scale": int(spec.scale), "const": int(spec.const),
            "x": [int(v) for v in xvals],
            "forms": list(forms),
        }
        if not self.runner:
            res.error = "Lattigo helper runner was not started"
            res.crash = True
            res.crash_kind = "runner-not-started"
            return res
        try:
            payload = self.runner.request(req)
        except RunnerFailure as exc:
            res.error = str(exc)
            res.crash = True
            res.crash_kind = exc.kind
            return res
        res.outputs = {k: [center_mod(int(v), self.plain_modulus)
                           for v in vals]
                       for k, vals in (payload.get("outputs") or {}).items()}
        res.noise_raw = payload.get("noise_raw")
        # The helper subtracts an independently encoded expected plaintext
        # before calling rlwe.Norm, matching Lattigo's own BGV noise tests.
        # A missing value is conservatively treated as exhausted budget.
        res.noise_ratio = (float(payload["noise_ratio"])
                           if payload.get("noise_ratio") is not None
                           else (1.0 if res.outputs else 0.0))
        res.meta = payload
        res.meta["helper_restarts"] = self.runner.restarts
        if payload.get("error"):
            res.error = str(payload["error"])
        if payload.get("crash"):
            res.crash = True
            res.crash_kind = "panic"
        return res
