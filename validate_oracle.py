#!/usr/bin/env python3
"""Oracle validation matrix.

Runs the fuzzer once with NO fault and once per injected fault, and checks the
two properties that make the oracle trustworthy:

  * **Sensitivity**  -- every injected fault is reported as a confirmed bug.
  * **Specificity**  -- the un-faulted target produces zero false positives.

This is the falsifiable claim that backstops "the fuzzer found nothing on the
real library": without this table, a silent oracle failure is indistinguishable
from a clean library.

    python3 validate_oracle.py --iterations 60 --seeds 3
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eidolon.engine import Eidolon          # noqa: E402
from eidolon.faults import FAULTS           # noqa: E402


def build(target_name: str, args):
    if target_name == "seal-bfv":
        from eidolon.targets.seal_bfv import SealBFVTarget
        return SealBFVTarget(poly_modulus_degree=args.poly_modulus_degree,
                             plain_bits=args.plain_bits)
    from eidolon.targets.concrete_fhe import ConcreteTarget
    return ConcreteTarget(bits=args.bits, slots=args.slots)


def one_run(target_name, fault, args, seed):
    target = build(target_name, args)
    if fault:
        target = FAULTS[fault](target)
    eng = Eidolon(target, seed=seed, repeats=args.repeats,
                  isolate=not args.no_isolate, verbose=False)
    stats = eng.run(iterations=args.iterations)
    kinds = [b.kind for b in eng.bugs]
    return eng.bugs, stats, kinds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="seal-bfv")
    ap.add_argument("--iterations", type=int, default=60)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--no-isolate", action="store_true")
    ap.add_argument("--poly-modulus-degree", type=int, default=8192)
    ap.add_argument("--plain-bits", type=int, default=20)
    ap.add_argument("--bits", type=int, default=6)
    ap.add_argument("--slots", type=int, default=None)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    faults = [None] + sorted(FAULTS)
    rows = []
    for fault in faults:
        total_bugs = 0
        total_correctness = 0
        total_crash = 0
        signals: set[str] = set()
        verdicts: dict[str, int] = {}
        for s in range(args.seeds):
            bugs, stats, kinds = one_run(args.target, fault, args, s)
            total_bugs += len(bugs)
            total_correctness += sum(1 for k in kinds if k == "correctness")
            total_crash += sum(1 for k in kinds if k == "crash")
            signals |= {b.signal for b in bugs}
            for k, v in stats["verdicts"].items():
                verdicts[k] = verdicts.get(k, 0) + v
        rows.append({
            "fault": fault or "(none)",
            "runs": args.seeds,
            "bugs_total": total_bugs,
            "correctness": total_correctness,
            "crash": total_crash,
            "signals": sorted(signals),
            "noise_overflow": verdicts.get("noise-overflow", 0),
        })

    hdr = f"{'fault':<16} {'runs':>4} {'bugs':>5} {'corr':>5} {'crash':>5} {'noise-of':>9}  signals"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['fault']:<16} {r['runs']:>4} {r['bugs_total']:>5} {r['correctness']:>5} "
              f"{r['crash']:>5} {r['noise_overflow']:>9}  {','.join(r['signals']) or '-'}")

    control = rows[0]
    injected = rows[1:]
    ok_sensitivity = all(r["bugs_total"] > 0 for r in injected)
    ok_specificity = control["bugs_total"] == 0
    print(f"\nsensitivity (every fault detected) : {'PASS' if ok_sensitivity else 'FAIL'}")
    print(f"specificity (no-fault -> 0 bugs)   : {'PASS' if ok_specificity else 'FAIL'}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0 if (ok_sensitivity and ok_specificity) else 1


if __name__ == "__main__":
    raise SystemExit(main())
