"""Execution adaptor for Microsoft SEAL BFV (via `tenseal.sealapi`).

Why this target
---------------
SEAL exposes `Decryptor.invariant_noise_budget()`, i.e. a *direct* residual-noise
read-out.  That makes it the faithful setting for Eidolon's core mechanism:
noise used as feedback to steer mutation (paper Sec. 4.2).  BFV is also an exact
integer scheme, so the native baseline is exact integer arithmetic reduced mod
the plaintext modulus -- a clean, unambiguous ground truth.

Lowering
--------
A sympy expression tree is walked bottom-up and emitted as SEAL API calls:

    symbol x        -> the encrypted input ciphertext
    pure constant   -> plaintext; combined with add_plain / multiply_plain
    Add             -> evaluator.add / add_plain
    Mul             -> evaluator.multiply + relinearize  (or multiply_plain)
    Pow(c, n)       -> square/multiply chain

`depth` is tracked so the engine can refuse expressions that cannot survive the
noise budget (that refusal is exactly the "noise-aware" part of the search).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import sympy as sp

from ..expr import ExprSpec, center_mod, native_eval
from .base import EvalResult, Target

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
# /tmp is deliberately not a fallback: it is an ephemeral location and made
# otherwise identical campaigns depend on whether the host happened to reboot.
# Keep the environment override for developers who intentionally use another
# wheel directory.
SEAL_LIB_PATH = os.environ.get(
    "FHE_SEAL_PATH", str(_PROJECT_ROOT / ".work" / "pylibs"))


def _import_seal():
    lib_path = Path(SEAL_LIB_PATH)
    if not lib_path.is_dir() or not (lib_path / "tenseal").is_dir():
        raise RuntimeError(
            "SEAL/TenSEAL bindings not found at "
            f"{lib_path}. Copy /tmp/fhe-libs to "
            f"{_PROJECT_ROOT / '.work' / 'pylibs'} or set FHE_SEAL_PATH "
            "to a complete binding directory.")
    if SEAL_LIB_PATH and SEAL_LIB_PATH not in sys.path:
        sys.path.insert(0, SEAL_LIB_PATH)
    import tenseal.sealapi as seal  # noqa: PLC0415

    return seal


class SealBFVTarget(Target):
    name = "seal-bfv"

    def __init__(
        self,
        poly_modulus_degree: int = 8192,
        plain_bits: int = 20,
        slots: int | None = None,
        seed: int | None = None,
    ):
        self.seal = _import_seal()
        self.N = poly_modulus_degree
        self.plain_bits = plain_bits
        self.slots = slots or (poly_modulus_degree // 2)
        self.seed = seed
        self.max_depth = 4
        self._ct_cls = self.seal.Ciphertext

    # -- lifecycle ------------------------------------------------------------
    def setup(self) -> None:
        # Keep this check in setup as well as in _import_seal: target setup is
        # the lifecycle boundary used by the runner and should fail with an
        # actionable message instead of a silent import fallback.
        lib_path = Path(SEAL_LIB_PATH)
        if not lib_path.is_dir() or not (lib_path / "tenseal").is_dir():
            raise RuntimeError(
                "seal-bfv setup requires a complete TenSEAL binding directory: "
                f"{lib_path}. Set FHE_SEAL_PATH or provision "
                f"{_PROJECT_ROOT / '.work' / 'pylibs'}.")
        seal = self.seal
        SL = seal.SEC_LEVEL_TYPE.TC128
        p = seal.EncryptionParameters(seal.SCHEME_TYPE.BFV)
        p.set_poly_modulus_degree(self.N)
        p.set_coeff_modulus(seal.CoeffModulus.BFVDefault(self.N, SL))
        p.set_plain_modulus(seal.PlainModulus.Batching(self.N, self.plain_bits))
        self.parms = p
        self.ctx = seal.SEALContext(p, True, SL)
        self.plain_modulus = p.plain_modulus().value()

        kg = seal.KeyGenerator(self.ctx)
        self.sk = kg.secret_key()
        self.pk = seal.PublicKey()
        kg.create_public_key(self.pk)
        self.relin = seal.RelinKeys()
        kg.create_relin_keys(self.relin)

        self.enc = seal.Encryptor(self.ctx, self.pk, self.sk)
        self.dec = seal.Decryptor(self.ctx, self.sk)
        self.encp = seal.BatchEncoder(self.ctx)
        self.ev = seal.Evaluator(self.ctx)
        self.eta0 = self.fresh_noise()
        # empirically: each ct*ct multiplication costs ~log2(t)+log2(N) bits
        budget = self.eta0
        self.max_depth = max(1, int(budget // (self.plain_bits + self.N.bit_length() - 1)))

    def fresh_noise(self) -> float:
        ct = self._encrypt_plaintext([0] * self.slots)
        return float(self.dec.invariant_noise_budget(ct))

    def close(self) -> None:
        pass

    # -- plaintext plumbing ---------------------------------------------------
    def _encode(self, vals: list[int]):
        seal = self.seal
        u = np.array([int(v) % self.plain_modulus for v in vals], dtype=np.uint64)
        pt = seal.Plaintext()
        self.encp.encode(u, pt)
        return pt

    def _encrypt_plaintext(self, vals: list[int]):
        ct = self.seal.Ciphertext()
        self.enc.encrypt(self._encode(vals), ct)
        return ct

    def _decrypt(self, ct) -> list[int] | None:
        """Decrypt + centre-mod.  Returns None when the noise has overflowed."""
        seal = self.seal
        out = seal.Plaintext()
        self.dec.decrypt(ct, out)
        raw = self.encp.decode_int64(out)
        t = self.plain_modulus
        return [center_mod(int(v), t) for v in raw]

    def _noise(self, ct) -> float:
        return float(self.dec.invariant_noise_budget(ct))

    # -- lowering -------------------------------------------------------------
    def _lower(self, expr: sp.Expr, xct):
        """Emit SEAL calls for `expr`.  Returns (ciphertext, multiplicative depth).

        The tree is walked bottom-up with memoisation on the sympy srepr, so a
        repeated subexpression is only evaluated once.  Any node we cannot
        express with the supported API is reported as `ValueError`, which the
        caller records as a lowering failure (not a bug).
        """
        ev = self.ev
        cls = self._ct_cls
        t = self.plain_modulus
        cache: dict[str, tuple] = {}

        def is_const(e: sp.Expr) -> bool:
            return not e.free_symbols

        def out_of_place(fn, *args):
            dst = cls()
            fn(*args, dst)
            return dst

        def walk(e: sp.Expr):
            if e == sp.Symbol("x"):
                return xct, 0
            key = sp.srepr(e)
            if key in cache:
                return cache[key]
            res = _walk(e)
            cache[key] = res
            return res

        def _walk(e: sp.Expr):
            if is_const(e):
                raise ValueError("bare constant (no ciphertext to anchor it)")

            if isinstance(e, sp.Add):
                ct, depth, csum = None, 0, 0
                for arg in e.args:
                    if is_const(arg):
                        csum += int(arg)
                        continue
                    sub, d = walk(arg)
                    if ct is None:
                        ct, depth = sub, d
                    else:
                        ct, depth = out_of_place(ev.add, ct, sub), max(depth, d)
                if ct is None:
                    raise ValueError("constant-only sum")
                c = csum % t
                if c:
                    ct = out_of_place(ev.add_plain, ct, self._encode([c] * self.slots))
                return ct, depth

            if isinstance(e, sp.Mul):
                ct, depth, consts = None, 0, 1
                for arg in e.args:
                    if is_const(arg):
                        consts *= int(arg)
                        continue
                    sub, d = walk(arg)
                    if ct is None:
                        ct, depth = sub, d
                    else:
                        ct = out_of_place(ev.multiply, ct, sub)
                        ev.relinearize_inplace(ct, self.relin)
                        depth = max(depth, d) + 1
                if ct is None:
                    raise ValueError("constant-only product")
                c = consts % t
                if c != 1:
                    ct = out_of_place(ev.multiply_plain, ct, self._encode([c] * self.slots))
                return ct, depth

            if isinstance(e, sp.Pow):
                base, ex = e.args
                n = int(ex)
                if n <= 0:
                    raise ValueError(f"non-positive exponent {n}")
                sub, d = walk(base)
                ct, depth = sub, d
                for _ in range(n - 1):
                    ct = out_of_place(ev.multiply, ct, sub)
                    ev.relinearize_inplace(ct, self.relin)
                    depth += 1
                return ct, depth

            raise ValueError(f"unsupported node {type(e).__name__}")

        return walk(expr)

    # -- evaluate -------------------------------------------------------------
    def evaluate(
        self,
        spec: ExprSpec,
        xvals: list[int],
        forms: dict[str, sp.Expr],
    ) -> EvalResult:
        res = EvalResult()
        coeffs = spec.coeffs()
        res.native = [center_mod(v, self.plain_modulus)
                      for v in native_eval(coeffs, xvals)]
        try:
            enc_pt = self._encode(xvals)
            noises: list[float] = []
            depths: dict[str, int] = {}
            for fname, fexpr in forms.items():
                xct = self._ct_cls()
                self.enc.encrypt(enc_pt, xct)
                try:
                    ct, depth = self._lower(fexpr, xct)
                except ValueError as e:
                    res.outputs[fname] = None
                    res.meta.setdefault("lower_errors", {})[fname] = str(e)
                    continue
                depths[fname] = depth
                n = self._noise(ct)
                noises.append(n)
                res.outputs[fname] = self._decrypt(ct) if n > 0 else None
            res.meta["depths"] = depths
            if noises:
                res.noise_raw = min(noises)
                res.noise_ratio = res.noise_raw / self.eta0 if self.eta0 else 0.0
        except Exception as e:  # noqa: BLE001 - we want everything
            res.error = self._err(e)
            res.crash = True
            res.crash_kind = type(e).__name__
            res.meta["traceback"] = self._tb(e)
        return res
