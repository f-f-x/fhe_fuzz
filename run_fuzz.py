#!/usr/bin/env python3
"""CLI for the Eidolon noise-aware FHE fuzzer.

Examples
--------
    # faithful Eidolon run against SEAL BFV (noise budget available)
    python3 run_fuzz.py --target seal-bfv --iterations 200 --report-dir runs/seal

    # oracle self-validation against a deliberately faulted target
    python3 run_fuzz.py --target seal-bfv --fault square --iterations 60

    # Zama Concrete (compiler-level equivalence oracle)
    python3 run_fuzz.py --target concrete --iterations 40 --report-dir runs/concrete
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eidolon.engine import Eidolon  # noqa: E402

#这里构建即可
def make_target(args):
    if args.target == "seal-bfv":
        from eidolon.targets.seal_bfv import SealBFVTarget
        return SealBFVTarget(poly_modulus_degree=args.poly_modulus_degree,
                             plain_bits=args.plain_bits, slots=args.slots)
    if args.target == "concrete":
        from eidolon.targets.concrete_fhe import ConcreteTarget
        return ConcreteTarget(bits=args.bits, slots=args.slots)
    if args.target == "lattigo-bgv":
        from eidolon.targets.lattigo_bgv import LattigoBGVTarget
        return LattigoBGVTarget(lattigo_root=args.lattigo_root, slots=args.slots)
    raise SystemExit(f"unknown target {args.target}")


def apply_fault(target, fault: str):
    """Wrap a target with an injected fault, to validate the oracle end to end."""
    from eidolon.faults import FAULTS
    if fault not in FAULTS:
        raise SystemExit(f"unknown fault {fault}; available: {sorted(FAULTS)}")
    return FAULTS[fault](target)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="seal-bfv",
                    choices=["seal-bfv", "concrete", "lattigo-bgv"])
    ap.add_argument("--iterations", type=int, default=None,
                    help="cases (default: 100; --calibrate default: 200)")
    ap.add_argument("--calibrate", action="store_true",
                    help="run a fault-free calibration pass and recommend tau P10/P70")
    ap.add_argument("--time-budget", type=float, default=None,
                    help="seconds; stops the loop when exceeded")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--tau-low", type=float, default=0.10)
    ap.add_argument("--tau-high", type=float, default=0.80)
    ap.add_argument("--repeats", type=int, default=3,
                    help="re-executions used to filter noise-induced false positives")
    ap.add_argument("--noise-floor", type=float, default=0.05,
                    help="residual-noise ratio below which output is not trusted")
    ap.add_argument("--case-timeout", type=float, default=120.0,
                    help="seconds allowed for one isolated evaluation")
    ap.add_argument("--max-corpus", type=int, default=10_000,
                    help="bound the evolving seed corpus (0 disables the bound)")
    ap.add_argument("--checkpoint-every", type=int, default=1_000,
                    help="write recoverable reports every N executed cases (0 disables)")
    ap.add_argument("--max-bugs", type=int, default=100,
                    help="cap saved bug artifacts during long campaigns")
    ap.add_argument("--no-isolate", action="store_true",
                    help="run evaluations in-process (no fork isolation)")
    ap.add_argument("--fault", default=None,
                    help="inject a known fault into the target (oracle self-test)")
    ap.add_argument("--report-dir", default=None)
    ap.add_argument("--quiet", action="store_true")

    ap.add_argument("--poly-modulus-degree", type=int, default=8192)
    ap.add_argument("--plain-bits", type=int, default=20)
    ap.add_argument("--bits", type=int, default=6, help="concrete: integer bit width")
    ap.add_argument("--slots", type=int, default=None)
    ap.add_argument("--lattigo-root", default=None,
                    help="Lattigo checkout used by the lattigo-bgv target")
    args = ap.parse_args()

    iterations = (args.iterations if args.iterations is not None
                  else (200 if args.calibrate else 100))
    if args.calibrate and args.fault:
        raise SystemExit("--calibrate is a pure exploration pass and cannot use --fault")

    target = make_target(args)
    fault = args.fault
    if fault:
        target = apply_fault(target, fault)
        print(f"[eidolon] fault injected: {fault}")

    eng = Eidolon(target, seed=args.seed, tau_low=args.tau_low,
                  tau_high=args.tau_high, repeats=args.repeats,
                  isolate=not args.no_isolate, slots=args.slots,
                  verbose=not args.quiet, noise_floor=args.noise_floor,
                  case_timeout=args.case_timeout, max_corpus=args.max_corpus,
                  checkpoint_every=args.checkpoint_every, max_bugs=args.max_bugs)
    report_dir = args.report_dir
    if args.calibrate and report_dir is None:
        report_dir = f"runs/calibration_{args.target}_{args.seed}"
    if not args.calibrate:
        print("[eidolon] warning: no calibration requested; using default "
              f"tau_low={args.tau_low:g}, tau_high={args.tau_high:g}")
    stats = eng.run(iterations=iterations, time_budget=args.time_budget,
                    report_dir=report_dir, calibration=args.calibrate)

    print("\n=== summary ===")
    print(json.dumps(stats, indent=2, default=str))
    if args.calibrate:
        print("\n=== calibration ===")
        print(json.dumps(stats.get("calibration"), indent=2, default=str))
    for b in eng.bugs:
        print(f"\n--- {b.case_id} [{b.kind}] {b.signal}")
        print(f"    expr     : {b.spec_repr}")
        print(f"    detail   : {b.detail}")
        print(f"    noise    : {b.noise_ratio}")
        print(f"    minimized: {b.minimized}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
