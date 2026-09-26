"""Probe: SEAL BFV ciphertext x plaintext multiplication with NEGATIVE plaintext.

Eidolon (FSE 2026, Fig. 2) reports a bug of exactly this shape in SEAL BFV:
`multiply_plain` / `multiply_plain_inplace` mishandles a plaintext that encodes
negative values.  This probe checks whether the SEAL that ships inside
tenseal 0.3.18 (SEAL 4.x) still exhibits it.
"""
import sys
import numpy as np

sys.path.insert(0, '/tmp/fhe-libs')
import tenseal.sealapi as seal

SL = seal.SEC_LEVEL_TYPE.TC128
N, bits = 8192, 20
p = seal.EncryptionParameters(seal.SCHEME_TYPE.BFV)
p.set_poly_modulus_degree(N)
p.set_coeff_modulus(seal.CoeffModulus.BFVDefault(N, SL))
p.set_plain_modulus(seal.PlainModulus.Batching(N, bits))
ctx = seal.SEALContext(p, True, SL)
t = p.plain_modulus().value()
print("plain_modulus t =", t)

kg = seal.KeyGenerator(ctx); sk = kg.secret_key()
pk = seal.PublicKey(); kg.create_public_key(pk)
relin = seal.RelinKeys(); kg.create_relin_keys(relin)
enc = seal.Encryptor(ctx, pk, sk); dec = seal.Decryptor(ctx, sk)
encp = seal.BatchEncoder(ctx); ev = seal.Evaluator(ctx)


def enc_pt(vals):
    pt = seal.Plaintext()
    encp.encode(np.array([int(v) % t for v in vals], dtype=np.uint64), pt)
    return pt


def enc_ct(vals):
    ct = seal.Ciphertext()
    enc.encrypt(enc_pt(vals), ct)
    return ct


def dec_ct(ct):
    out = seal.Plaintext()
    dec.decrypt(ct, out)
    return [(int(v) if int(v) < t // 2 else int(v) - t)
            for v in encp.decode_int64(out)]


x   = [1, 2, 3, 4, 5, 6, 7, 8, 100, -100, 1000, -1000, 12345, -12345, 0, 7]
mul = [-1, -2, -3, -4, 5, 6, -7, 8, -1, 1, -2, 2, -3, 3, 0, -1]

expect = [a * b for a, b in zip(x, mul)]

# ---- (a) out-of-place multiply_plain --------------------------------------
ct_a = enc_ct(x)
dst = seal.Ciphertext()
ev.multiply_plain(ct_a, enc_pt(mul), dst)
got_a = dec_ct(dst)

# ---- (b) in-place multiply_plain_inplace ----------------------------------
ct_b = enc_ct(x)
ev.multiply_plain_inplace(ct_b, enc_pt(mul))
got_b = dec_ct(ct_b)

# ---- (c) same with a plaintext built via a uniform constructor (no batch) --
# sanity control: multiply by a NON-negative plaintext should be fine
mul_pos = [abs(v) + 1 for v in mul]
ct_c = enc_ct(x)
ev.multiply_plain_inplace(ct_c, enc_pt(mul_pos))
got_c = dec_ct(ct_c)
expect_c = [a * b for a, b in zip(x, mul_pos)]


def report(name, got, exp):
    bad = [(i, g, e) for i, (g, e) in enumerate(zip(got, exp)) if g != e]
    print(f"\n[{name}] mismatches: {len(bad)}")
    for i, g, e in bad[:8]:
        print(f"   slot {i:2d}: got {g:12d}  expected {e:12d}")
    return bad


b1 = report("multiply_plain (out-of-place, negative plaintext)", got_a, expect)
b2 = report("multiply_plain_inplace (negative plaintext)", got_b, expect)
b3 = report("CONTROL multiply_plain_inplace (positive plaintext)", got_c, expect_c)
print("\nRESULT:", "BUG REPRODUCED" if (b1 or b2) else "no discrepancy in this probe")
