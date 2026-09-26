"""Eidolon's noise-aware fuzzing loop (paper Algorithm 1) + bug confirmation.

    while true:
        if residual_noise < tau_low:  base = LowNoiseMutator(base)
        else:                         base = HighNoiseMutator(base)
        {std, hor, fac} = Transform(base)
        result = Execute(forms, keys)
        noise  = residual_noise(result)
        bugs  += Check(result)
        if decryptable: corpus.append(base)

Everything in this file is library-agnostic; the only target-specific piece is
the `Target` implementation plugged in at construction time.
"""
from __future__ import annotations

import json
import os
import pickle
import random
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

import sympy as sp

from . import oracle
from .corpus import Corpus
from .expr import ExprSpec, distinct_forms
from .mutator import clamp, mutate, simplify
from .targets.base import EvalResult, Target

TAU_LOW = 0.10   # paper: tau_low  = 0.1 * eta_0
TAU_HIGH = 0.80  # paper: tau_high = 0.8 * eta_0


@dataclass
class BugCase:
    case_id: str
    kind: str                 # "correctness" | "crash"
    detail: str
    signal: str
    spec_repr: str
    coeffs: list[int]
    xvals: list[int]
    forms: dict[str, str] = field(default_factory=dict)
    native: list[int] = field(default_factory=list)
    outputs: dict[str, list[int] | None] = field(default_factory=dict)
    mismatch_counts: dict[str, int] = field(default_factory=dict)
    noise_ratio: float | None = None
    iteration: int = 0
    confirmed_repeats: int = 0
    minimized: bool = False
    meta: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------------------
# crash isolation: run one evaluation in a forked child
# ---------------------------------------------------------------------------

def _run_isolated(fn, timeout: float = 120.0):
    """Execute `fn` in a child process so a SIGSEGV / abort is survivable.

    Returns (result, crash_kind).  `crash_kind` is non-empty when the child died
    from a signal -- that is Eidolon's "crash bug" class.

    Two details here are load-bearing and were each learned from a hang:

    * **Never block waiting for EOF.**  A library's crash handler may fork an
      external symbolizer (LLVM does, on SIGSEGV) which *inherits the pipe's
      write end*.  The child is dead, but that grandchild keeps the write end
      open, so a blocking `read()` never sees EOF and the fuzzer hangs forever
      on a case it already knows is a crash.  We therefore poll instead: the
      authoritative "the child is finished" signal is `waitpid`, not EOF.

    * **Enforce the timeout.**  `timeout` used to be computed into a `deadline`
      that nothing ever read, so a wedged child wedged the campaign.  Now it
      kills the child and reports the case as a timeout.
    """
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        try:
            os.close(r)
            try:
                res = fn()
                blob = pickle.dumps((res, None))
            except BaseException as e:  # noqa: BLE001
                blob = pickle.dumps((None, f"{type(e).__name__}: {e}"))
            os.write(w, len(blob).to_bytes(8, "little"))
            os.write(w, blob)
            os.close(w)
        finally:
            os._exit(0)

    os.close(w)
    os.set_blocking(r, False)
    deadline = time.time() + timeout
    chunks: list[bytes] = []
    status = None
    timed_out = False

    def drain() -> None:
        while True:
            try:
                b = os.read(r, 1 << 20)
            except BlockingIOError:
                return
            except OSError:
                return
            if not b:
                return
            chunks.append(b)

    while True:
        drain()
        wpid, st = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            status = st
            drain()          # the child may have written its blob just before exiting
            break
        if time.time() > deadline:
            timed_out = True
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            break
        time.sleep(0.005)

    os.close(r)

    if timed_out:
        return None, f"timeout after {timeout:g}s"
    data = b"".join(chunks)
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        return None, f"signal {sig} ({signal.Signals(sig).name})"
    if len(data) < 8:
        return None, "child died without result"
    n = int.from_bytes(data[:8], "little")
    payload = data[8:8 + n]
    try:
        res, err = pickle.loads(payload)
    except Exception as e:  # noqa: BLE001
        return None, f"unpickle failed: {e}"
    if res is None:
        return None, f"exception: {err}"
    return res, ""


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class Eidolon:
    def __init__(
        self,
        target: Target,
        *,
        seed: int = 0,
        tau_low: float = TAU_LOW,
        tau_high: float = TAU_HIGH,
        repeats: int = 3,
        isolate: bool = True,
        slots: int | None = None,
        verbose: bool = True,
        noise_floor: float = 0.05,
        case_timeout: float = 120.0,
        max_corpus: int = 10_000,
        checkpoint_every: int = 1_000,
        max_bugs: int = 100,
    ):
        self.target = target
        self.rng = random.Random(seed)
        self.tau_low = tau_low
        self.tau_high = tau_high
        self.repeats = repeats
        self.isolate = isolate
        self.verbose = verbose
        self.noise_floor = noise_floor
        self.case_timeout = case_timeout
        self.max_corpus = max_corpus
        self.checkpoint_every = checkpoint_every
        self.max_bugs = max_bugs
        # Targets may provide library-specific seeds extracted from their
        # official examples/tests.  Keeping them on the target avoids changing
        # the search space of unrelated libraries.
        self.corpus = Corpus(self.rng,
                             extra_seeds=getattr(target, "seed_specs", None),
                             case_states=target.seed_case_states())
        self.bugs: list[BugCase] = []
        self._bug_keys: set[tuple] = set()
        self.history: list[dict] = []
        self.noise_ratio: float | None = None
        self.eta0: float = 0.0
        self._slots = slots
        self._schema = {
            "ok": 0, "noise-overflow": 0, "crash": 0,
            "candidate": 0, "confirmed": 0, "rejected": 0,
        }
        self._suppressed_bugs = 0
        self._degree_hist: dict[str, int] = {}
        self._params_hist: dict[str, int] = {}
        self._postfix_hist: dict[str, int] = {}
        self._scale_invariant_hist: dict[str, int] = {}
        self._clamped = 0
        self._discarded_after_clamp = 0
        self.calibration: dict | None = None

    # -- slot values ----------------------------------------------------------
    def _make_xvals(self) -> list[int]:
        """Slot payload: a spread of boundary-ish magnitudes.

        Boundary inputs are what the paper credits for finding the OpenFHE CKKS
        boundary bug and the SEAL CKKS encoding bugs, so they are always present.
        """
        n = self._slots or self.target.slots
        t = self.target.plain_modulus
        base = [0, 1, -1, 2, -2, 3, -3, 4, -4, 7, -7, 8, -8, 15, -15, 16, -16,
                31, -31, 63, -63, 127, -127, 255, -255]
        vals = list(base)
        while len(vals) < n:
            vals.append(self.rng.randint(-256, 256))
        if t:
            # values that sit at the edge of the plaintext modulus representation
            edge = [t // 2, t // 2 - 1, -(t // 2) + 1, t // 4, -(t // 4),
                    t // 2 - 3, 2, -2]
            for i, e in enumerate(edge):
                vals[i % n] = e
        return vals[:n]

    # -- one test case --------------------------------------------------------
    def _evaluate(self, spec: ExprSpec, forms: dict[str, sp.Expr], xvals,
                  state: dict | None = None, *, injected_fault: str | None = None,
                  fault_forms: tuple[str, ...] = ()) -> EvalResult:
        state = state or {}

        def invoke():
            return self.target.evaluate_case(spec, xvals, forms, state,
                                             injected_fault=injected_fault,
                                             fault_forms=fault_forms)

        if self.target.manages_isolation:
            try:
                return invoke()
            except BaseException as e:  # native target runner owns process safety
                r = EvalResult()
                r.error = f"{type(e).__name__}: {e}"
                r.crash = True
                r.crash_kind = type(e).__name__
                return r
        if not self.isolate:
            try:
                return invoke()
            except BaseException as e:  # noqa: BLE001
                r = EvalResult()
                r.error = f"{type(e).__name__}: {e}"
                r.crash = True
                r.crash_kind = type(e).__name__
                return r

        res, crash = _run_isolated(
            invoke, timeout=self.case_timeout)
        if crash:
            r = EvalResult()
            r.crash = True
            r.crash_kind = crash
            r.error = f"target died: {crash}"
            if crash.startswith("exception:"):
                r.crash = True
            return r
        return res

    # -- minimisation (MWE) ---------------------------------------------------
    def _shrink(self, case: BugCase, state: dict, forms_src: str = "") -> None:
        """Greedy structural reduction that preserves the deviation pattern."""
        spec = ExprSpec(tuple((a, b) for a, b in _parse_factors(case.spec_repr)),
                        case.meta.get("scale", 1), case.meta.get("const", 0))
        # The MWE must reproduce *this* deviation, not merely some deviation: a
        # shrink that drifts onto a different (form, slot) pattern would produce
        # a minimal example that no longer demonstrates the reported bug.  The
        # original signature therefore has to be the acceptance criterion.
        target_sig = frozenset(
            (f, s) for f, slots in (case.meta.get("mismatch_slots") or {}).items()
            for s in slots
        )

        best = spec
        xvals = case.xvals
        for _ in range(12):
            cand = simplify(best, self.rng)
            if cand == best:
                break
            forms = distinct_forms(cand)
            res = self._evaluate(cand, forms, xvals, state)
            v = oracle.analyse(res, self.noise_floor)
            if v.kind is oracle.Kind.CRASH:
                best = cand
            elif v.kind is oracle.Kind.CANDIDATE and (
                not target_sig or oracle.overlap(v.signature(), target_sig) >= 0.5
            ):
                best = cand
            else:
                break
        if best != spec:
            case.spec_repr = str(best)
            case.coeffs = best.coeffs()
            case.minimized = True
            case.meta["scale"] = best.scale
            case.meta["const"] = best.const

    # -- main loop ------------------------------------------------------------
    def run(self, iterations: int = 200, time_budget: float | None = None,
            report_dir: str | Path | None = None,
            calibration: bool = False) -> dict:
        self.target.setup()
        self.eta0 = self.target.fresh_noise()
        if self.verbose:
            print(f"[eidolon] target={self.target.name} eta0={self.eta0} "
                  f"t={self.target.plain_modulus} slots={self._slots or self.target.slots} "
                  f"max_depth~{self.target.max_depth}")

        base = self.corpus.select()
        # Generic targets retain one fixed boundary vector for a campaign. A
        # target with an input-dependent plaintext ring (Lattigo parameter
        # search) can opt into a per-case vector through make_xvals_for_case.
        default_xvals = self._make_xvals()
        t0 = time.time()

        for it in range(iterations):
            if time_budget and (time.time() - t0) > time_budget:
                break

            # (steps 3) noise-aware mutator selection
            mode = "low" if (self.noise_ratio is not None
                             and self.noise_ratio < self.tau_low) else "high"
            spec = mutate(base.spec, self.rng, mode)
            state = self.target.mutate_case(base, self.rng, mode)
            base.hits += 1

            # The multiplicative ceiling is a property of the selected FHE
            # parameters, not of ExprSpec.  The default hook keeps legacy
            # targets on their existing target.max_depth setting.
            max_depth = self.target.max_depth_for_case(state)

            if spec.degree() > max_depth:
                bounded = clamp(spec, max_depth)
                if bounded != spec:
                    self._clamped += 1
                spec = bounded

            # Keep a small amount of headroom when a high-noise mutation lands
            # exactly on the ceiling.  Without this, a seed at max_depth can
            # repeatedly receive mutations that are rejected/no-op and the
            # observed degree distribution collapses at the ceiling.  This is
            # still the requested mutator constraint: it does not change the
            # oracle or synthesize a fresh unrelated seed.
            if (spec.degree() >= max_depth and mode == "high"
                    and max_depth > 0
                    # Retain a small, deterministic-by-seed sample exactly at
                    # the legal ceiling.  This keeps valid boundary cases
                    # reachable (including the crash-deep oracle self-test),
                    # while most high-mode mutations get headroom below it.
                    and self.rng.random() < 0.75):
                bounded = clamp(spec, max_depth - 1)
                if bounded != spec:
                    self._clamped += 1
                spec = bounded

            if spec.degree() > max_depth:
                self._discarded_after_clamp += 1
                continue

            degree_key = str(spec.degree())
            self._degree_hist[degree_key] = self._degree_hist.get(degree_key, 0) + 1
            params_key = str(state.get("params_id") or "default")
            self._params_hist[params_key] = self._params_hist.get(params_key, 0) + 1
            postfix_key = str(state.get("postfix") or "identity")
            self._postfix_hist[postfix_key] = self._postfix_hist.get(postfix_key, 0) + 1
            si_key = "bfv-scale-invariant" if state.get("scale_invariant") else "bgv"
            self._scale_invariant_hist[si_key] = self._scale_invariant_hist.get(si_key, 0) + 1

            # (step 4) equivalence expression transformation
            forms = distinct_forms(spec)
            if not forms:
                continue

            # (steps 5-6) execute + consistency check
            xvals = self.target.make_xvals_for_case(
                self.rng, self._slots or self.target.slots, state) or default_xvals
            res = self._evaluate(spec, forms, xvals, state)
            verdict = oracle.analyse(res, self.noise_floor)

            # (steps 7-8) noise monitor + handlers
            if res.noise_ratio is not None and not res.crash:
                self.noise_ratio = res.noise_ratio
                if verdict.kind is oracle.Kind.NOISE_OVERFLOW:
                    self.corpus.penalise(spec, **state)
                else:
                    self.corpus.reward(spec, res.noise_ratio,
                                       self.tau_low, self.tau_high, **state)
            else:
                self.noise_ratio = None

            self._schema[verdict.kind.value] = self._schema.get(verdict.kind.value, 0) + 1

            # (step 9) coverage of the expression space + bug handling
            if verdict.kind is oracle.Kind.CANDIDATE:
                self._consider_candidate(spec, forms, xvals, res, verdict, it, state)
            elif verdict.kind is oracle.Kind.CRASH:
                self._record_crash(spec, forms, xvals, res, it, state)

            self.history.append({
                "iter": it, "expr": str(spec), "degree": spec.degree(),
                "depth": res.meta.get("depths"), "noise_ratio": res.noise_ratio,
                "levels": res.meta.get("levels"), "params_id": state.get("params_id"),
                "postfix": state.get("postfix", "identity"),
                "postfix_arg": state.get("postfix_arg", 0),
                "scale_invariant": bool(state.get("scale_invariant")),
                "max_depth": max_depth, "verdict": verdict.kind.value,
            })

            # Seed-corpus feedback (step 9): a seed that executed cleanly becomes
            # the new base, so the walk actually descends into the computational
            # space instead of re-mutating the initial seed forever.  Every so
            # often we jump back to a corpus-chosen seed to stay diverse.
            if verdict.kind in (oracle.Kind.OK, oracle.Kind.CANDIDATE):
                if self.rng.random() < 0.15:
                    base = self.corpus.select()
                else:
                    base = self.corpus.add(spec, **state)
            elif verdict.kind is oracle.Kind.NOISE_OVERFLOW:
                base = self.corpus.select()
            if self.max_corpus and len(self.corpus) > self.max_corpus:
                self.corpus.prune(self.max_corpus)
            if report_dir and self.checkpoint_every and (it + 1) % self.checkpoint_every == 0:
                checkpoint_stats = self._stats(time.time() - t0)
                self._dump(report_dir, checkpoint_stats)
            if self.verbose and (it % 25 == 0 or verdict.interesting):
                print(f"[{it:5d}] {verdict.kind.value:15s} noise={res.noise_ratio!s:>6.3} "
                      f"deg={spec.degree():2d} mode={mode:4s} {str(spec)[:60]}")

        if calibration:
            self.calibration = self._build_calibration()
        stats = self._stats(time.time() - t0)
        if report_dir:
            self._dump(report_dir, stats)
        self.target.close()
        return stats

    @staticmethod
    def _quantile(values: list[float], q: float) -> float:
        if not values:
            raise ValueError("cannot calculate a quantile of an empty sample")
        ordered = sorted(values)
        pos = (len(ordered) - 1) * q
        lo = int(pos)
        hi = min(lo + 1, len(ordered) - 1)
        frac = pos - lo
        return ordered[lo] + (ordered[hi] - ordered[lo]) * frac

    def _build_calibration(self) -> dict:
        values = [float(row["noise_ratio"]) for row in self.history
                  if row.get("noise_ratio") is not None]
        if not values:
            return {
                "status": "insufficient-data",
                "samples": 0,
                "reason": "no evaluation returned a noise_ratio",
            }
        quantiles = {f"p{int(q * 100)}": round(self._quantile(values, q), 8)
                     for q in (0.10, 0.25, 0.50, 0.70, 0.90)}
        tau_low = quantiles["p10"]
        tau_high = quantiles["p70"]
        boundary = self.corpus.mark_calibrated_boundaries(tau_low)
        return {
            "status": "ok",
            "samples": len(values),
            "quantiles": quantiles,
            "recommended_tau_low": tau_low,
            "recommended_tau_high": tau_high,
            "boundary_seeds_marked": boundary,
            "method": "P10/P70 of observed residual noise ratio",
        }

    def _stats(self, elapsed: float) -> dict:
        return {
            "target": self.target.name,
            "iterations": len(self.history),
            "eta0": self.eta0,
            "verdicts": self._schema,
            "bugs": len(self.bugs),
            "suppressed_bugs": self._suppressed_bugs,
            "corpus": self.corpus.stats(),
            "degree_distribution": dict(sorted(self._degree_hist.items(),
                                                 key=lambda kv: int(kv[0]))),
            "params_id_distribution": dict(sorted(self._params_hist.items())),
            "postfix_distribution": dict(sorted(self._postfix_hist.items())),
            "scale_invariant_distribution": dict(sorted(self._scale_invariant_hist.items())),
            "clamped_cases": self._clamped,
            "discarded_after_clamp": self._discarded_after_clamp,
            "calibration": self.calibration,
            "target_metadata": self.target.run_metadata(),
            "elapsed_s": round(elapsed, 2),
        }

    # -- bug bookkeeping ------------------------------------------------------
    @staticmethod
    def _state_key(state: dict) -> tuple:
        return (state.get("params_id"), state.get("postfix", "identity"),
                int(state.get("postfix_arg", 0)), bool(state.get("scale_invariant")))

    def _bug_key(self, spec: ExprSpec, verdict, state: dict) -> tuple:
        return (spec.canonical(), verdict.kind.value, self._state_key(state))

    def _consider_candidate(self, spec, forms, xvals, res, verdict, it, state):
        """Apply the re-execution filter before believing a mismatch."""
        sigs = [verdict.signature()]
        for _ in range(self.repeats - 1):
            res2 = self._evaluate(spec, forms, xvals, state)
            v2 = oracle.analyse(res2, self.noise_floor)
            if v2.kind is oracle.Kind.CRASH:
                self._record_crash(spec, forms, xvals, res2, it, state)
                return
            if v2.kind is not oracle.Kind.CANDIDATE:
                sigs.append(frozenset())
                continue
            sigs.append(v2.signature())

        if not oracle.confirm(sigs, min_agree=2):
            self._schema["rejected"] += 1
            if self.verbose:
                print(f"        -> rejected (did not persist across re-execution)")
            self.corpus.penalise(spec, 0.5, **state)
            return

        key = self._bug_key(spec, verdict, state)
        if key in self._bug_keys:
            return
        if len(self.bugs) >= self.max_bugs:
            self._suppressed_bugs += 1
            return
        self._bug_keys.add(key)
        self._schema["confirmed"] += 1
        case = BugCase(
            case_id=f"bug{len(self.bugs):03d}",
            kind="correctness",
            detail=verdict.detail,
            signal=verdict.signal,
            spec_repr=str(spec),
            coeffs=spec.coeffs(),
            xvals=xvals,
            forms={k: str(v) for k, v in forms.items()},
            native=res.native,
            outputs={k: (v[:16] if v else None) for k, v in res.outputs.items()},
            mismatch_counts=verdict.mismatch_counts,
            noise_ratio=res.noise_ratio,
            iteration=it,
            confirmed_repeats=self.repeats,
            meta={"scale": spec.scale, "const": spec.const,
                  "mismatch_slots": verdict.mismatch_slots,
                  "depths": res.meta.get("depths"),
                  "levels": res.meta.get("levels"),
                  "noise_by_form": res.meta.get("noise_by_form"),
                  "params_id": state.get("params_id"),
                  "postfix": state.get("postfix", "identity"),
                  "postfix_arg": state.get("postfix_arg", 0),
                  "scale_invariant": bool(state.get("scale_invariant")),
                  "target": self.target.name,
                  "plain_modulus": res.meta.get("plain_modulus", self.target.plain_modulus),
                  "forms_agree_with_each_other": verdict.forms_agree_with_each_other,
                  "out_dtypes": res.meta.get("out_dtypes"),
                  "natives": res.natives or None},
        )
        self.bugs.append(case)
        if self.verbose:
            print(f"        -> CONFIRMED {case.kind} bug: {verdict.detail}")
        try:
            self._shrink(case, state)
        except Exception as e:  # noqa: BLE001 - minimisation is best effort
            case.meta["shrink_error"] = f"{type(e).__name__}: {e}"

    def _record_crash(self, spec, forms, xvals, res, it, state):
        key = (spec.canonical(), "crash", res.crash_kind, self._state_key(state))
        if key in self._bug_keys:
            return
        if len(self.bugs) >= self.max_bugs:
            self._suppressed_bugs += 1
            return
        self._bug_keys.add(key)
        self._schema["confirmed"] += 1
        case = BugCase(
            case_id=f"bug{len(self.bugs):03d}",
            kind="crash",
            detail=res.error or "crash",
            signal=res.crash_kind,
            spec_repr=str(spec),
            coeffs=spec.coeffs(),
            xvals=xvals[:64],
            forms={k: str(v) for k, v in forms.items()},
            native=res.native[:64],
            outputs={},
            noise_ratio=res.noise_ratio,
            iteration=it,
            meta={"target": self.target.name,
                  "plain_modulus": res.meta.get("plain_modulus", self.target.plain_modulus),
                  "depths": res.meta.get("depths"),
                  "levels": res.meta.get("levels"),
                  "params_id": state.get("params_id"),
                  "postfix": state.get("postfix", "identity"),
                  "postfix_arg": state.get("postfix_arg", 0),
                  "scale_invariant": bool(state.get("scale_invariant"))},
        )
        self.bugs.append(case)
        if self.verbose:
            print(f"        -> CRASH {res.crash_kind}: {case.detail[:80]}")

    # -- persistence ----------------------------------------------------------
    def _dump(self, report_dir, stats):
        d = Path(report_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "bugs.json").write_text(
            json.dumps([b.to_json() for b in self.bugs], indent=2, default=str),
            encoding="utf-8")
        (d / "run.json").write_text(json.dumps(stats, indent=2, default=str),
                                    encoding="utf-8")
        with (d / "history.jsonl").open("w", encoding="utf-8") as f:
            for row in self.history:
                f.write(json.dumps(row, default=str) + "\n")
        self.corpus.dump(d / "corpus.json")


def _parse_factors(spec_repr: str) -> list[tuple[int, int]]:
    import re
    return [(int(a), int(b))
            for a, b in re.findall(r"\((-?\d+)x([+-]\d+)\)", spec_repr)]
