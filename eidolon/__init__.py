"""Eidolon: noise-aware fuzzing for FHE libraries.

An implementation of the design in

  Xian, Yan, Chen, Cao, Ma, Shi, Jiang.
  "Eidolon: Perform Noise-Aware Fuzzing on FHE Libraries via Equivalence
   Expression Transformation", Proc. ACM Softw. Eng. 3, FSE, Article FSE102 (2026).
  DOI 10.1145/3808109

Modules mirror the paper's components:

  expr       -- arithmetic expressions + Equivalence Expression Transformation
  mutator    -- High-Noise / Low-Noise mutators
  corpus     -- evolving seed corpus with noise-driven prioritisation
  oracle     -- the equivalence oracle + re-execution false-positive filter
  engine     -- the noise-aware fuzzing loop (Algorithm 1)
  targets/   -- Execution Adaptors (the only library-specific part)
"""
