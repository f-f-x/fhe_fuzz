"""The Equivalence Expression Transformation oracle (paper Sec. 4.4).

The whole point of the oracle is to tell an *implementation bug* apart from an
*expected noise-induced decryption failure* without any external ground truth.

Three sources of evidence are combined:

1. **Native baseline.**  The same polynomial evaluated in exact integer
   arithmetic, reduced into the scheme's plaintext-modulus semantics.  A single
   form disagreeing with it is *not* yet a bug (noise can corrupt a result).

2. **Cross-form consistency.** Standard / Factored / Horner are mathematically
   identical but take different execution paths. A selective divergence is a
   useful signal, but it is only a candidate: the lowering paths consume
   different amounts of noise, so a near-exhausted form can fail first.

3. **Re-execution.**  A genuine implementation bug is *deterministic*: it
   reproduces from the same expression and inputs.  Noise overflow is
   *stochastic*: fresh encryption randomness reshuffles which slots fail.  So a
   candidate is only confirmed when the same (form, slot) deviation pattern
   survives repeated re-execution -- the paper's false-positive filter, which
   took their raw 1,284 mismatches down to 148.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .targets.base import EvalResult

#: how many (form, slot) pairs survive into the re-execution signature
SIG_WIDTH = 64


class Kind(str, Enum):
    OK = "ok"
    NOISE_OVERFLOW = "noise-overflow"
    CRASH = "crash"
    CANDIDATE = "candidate"


@dataclass
class Verdict:
    kind: Kind
    detail: str = ""
    #: form -> number of slots whose decrypted value != native
    mismatch_counts: dict[str, int] = field(default_factory=dict)
    #: form -> first few mismatching slot indices
    mismatch_slots: dict[str, list[int]] = field(default_factory=dict)
    #: which forms agreed with the native baseline
    agreeing: list[str] = field(default_factory=list)
    signal: str = ""
    #: True when every decryptable form produced *byte-identical* output.
    #: A strong hint that the divergence lives in the baseline rather than in
    #: the library: independent lowering paths landing on one shared wrong value
    #: is far less likely than the harness's model of the plaintext ring being
    #: wrong.  Recorded, never used to suppress -- the re-execution filter and a
    #: human still decide.
    forms_agree_with_each_other: bool = False

    @property
    def interesting(self) -> bool:
        return self.kind in (Kind.CANDIDATE, Kind.CRASH)

    def signature(self) -> frozenset:
        pairs = []
        for form, slots in self.mismatch_slots.items():
            for s in slots[:SIG_WIDTH]:
                pairs.append((form, s))
        return frozenset(pairs)


def analyse(res: EvalResult, noise_floor: float = 0.05) -> Verdict:
    """Classify one execution's raw outcome."""
    if res.crash:
        return Verdict(Kind.CRASH, detail=res.error or "crash",
                       signal=res.crash_kind)

    # A residual-noise measurement is stronger evidence than the decrypted
    # values themselves.  Classify these runs before looking at form output:
    # an equivalent but noisier lowering can legitimately be the first form to
    # decrypt incorrectly.  This is the critical filter missing from the
    # original adapter, which had no residual-noise signal for Lattigo BGV.
    if res.noise_ratio is None or res.noise_ratio < noise_floor:
        ratio = "unknown" if res.noise_ratio is None else f"{res.noise_ratio:.3g}"
        return Verdict(Kind.NOISE_OVERFLOW,
                       detail=f"residual noise below reliable threshold ({ratio})",
                       signal="residual-noise")

    forms = {k: v for k, v in res.outputs.items() if v is not None}
    if not forms:
        return Verdict(Kind.NOISE_OVERFLOW,
                       detail="no form decrypted (noise budget exhausted)",
                       signal="all-undecryptable")

    counts: dict[str, int] = {}
    slots: dict[str, list[int]] = {}
    for form, out in forms.items():
        # Per-form baseline when the target provides one (targets whose forms do
        # not share a single modular semantics); otherwise the common baseline.
        baseline = res.natives.get(form, res.native) if res.natives else res.native
        bad = [i for i, (g, e) in enumerate(zip(out, baseline)) if g != e]
        if bad:
            counts[form] = len(bad)
            slots[form] = bad[:SIG_WIDTH]

    agreeing = [f for f in forms if f not in counts]

    if not counts:
        return Verdict(Kind.OK, agreeing=agreeing, mismatch_counts={},
                       mismatch_slots={}, signal="consistent")

    # --- deviation pattern ---------------------------------------------------
    # Selectivity is informative, but can still come from one lowering reaching
    # the noise boundary first; confirmation additionally rechecks residual
    # noise on every fresh encryption.
    if agreeing:
        signal = "cross-form"          # some forms right, others wrong
        detail = (f"forms {sorted(counts)} deviate from native while "
                  f"{agreeing} agree")
    else:
        # every decryptable form is wrong.  Still possible that the expression
        # simply exhausted the noise while returning non-zero budget; the
        # re-execution filter decides.
        signal = "uniform"
        detail = f"all decryptable forms {sorted(counts)} deviate from native"

    # Do the forms agree with *each other*, even though they disagree with the
    # baseline?  If so, say so -- it is the signature of a baseline artefact
    # (a wrong model of the plaintext ring) rather than of a miscompilation,
    # because a real bug in one rewrite path leaves the others correct.
    uniq = {tuple(v) for v in forms.values()}
    agree_each_other = len(uniq) == 1 and len(forms) > 1
    if agree_each_other:
        detail += ("; all forms returned identical output -- the shared "
                   "divergence is between the harness baseline and the "
                   "library's own ring, inspect before trusting")

    return Verdict(Kind.CANDIDATE, detail=detail, mismatch_counts=counts,
                   mismatch_slots=slots, agreeing=agreeing, signal=signal,
                   forms_agree_with_each_other=agree_each_other)


def overlap(a: frozenset, b: frozenset) -> float:
    """Jaccard similarity of two deviation signatures (0.0 when both empty)."""
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def confirm(signatures: list[frozenset], min_agree: int = 2) -> bool:
    """Re-execution filter: did the deviation pattern persist?

    `signatures` are the per-run signatures of an initial candidate plus its
    re-executions.  A deterministic bug yields near-identical sets; a stochastic
    noise failure does not.
    """
    if len(signatures) < min_agree:
        return False
    ref = signatures[0]
    if not ref:
        return False
    hits = 0
    for sig in signatures[1:]:
        if overlap(ref, sig) >= 0.5:
            hits += 1
    return hits >= (len(signatures) - 1) * 0.5


def is_noise_dominated(res: EvalResult, tau: float = 0.05) -> bool:
    """Heuristic: the residual noise is so low the run is unreliable."""
    if res.noise_ratio is None:
        return True
    return res.noise_ratio < tau
