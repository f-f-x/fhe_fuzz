#!/usr/bin/env python3
"""Replay a Go-native fuzz artifact through Eidolon's Python oracle.

Usage:
  GO=/path/to/go125/bin/go python3 replay_go_case.py artifact.json \
      --lattigo-root /path/to/.work/lattigo
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eidolon.expr import ExprSpec, distinct_forms
from eidolon.oracle import analyse
from eidolon.targets.lattigo_bgv import LattigoBGVTarget


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact")
    ap.add_argument("--lattigo-root", default=None)
    ap.add_argument("--noise-floor", type=float, default=0.05)
    args = ap.parse_args()
    p = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    if p.get("source") == "decode_destination":
        print(json.dumps({"verdict": "native-only",
                          "detail": "malformed ring.Poly destination requires the Go API probe; it is not a polynomial-expression case"}, indent=2))
        return 0
    spec = ExprSpec(tuple(tuple(int(x) for x in f) for f in p.get("factors", [])),
                    int(p.get("scale", 1)), int(p.get("const", 0)))
    target = LattigoBGVTarget(lattigo_root=args.lattigo_root,
                              slots=len(p.get("x", [])))
    target.setup()
    try:
        result = target.evaluate(spec, [int(x) for x in p.get("x", [])],
                                 distinct_forms(spec))
        verdict = analyse(result, args.noise_floor)
        print(json.dumps({"verdict": verdict.kind.value,
                          "detail": verdict.detail,
                          "signal": verdict.signal,
                          "noise_ratio": result.noise_ratio,
                          "outputs": result.outputs}, indent=2, default=str))
    finally:
        target.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
