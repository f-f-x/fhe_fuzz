#!/bin/bash
# Build binfhe_probe twice: plain and ASAN+UBSAN.
set -euo pipefail

ROOT=/home/ffx/fuzz-lab2/fhe_fuzz/probes/openfhe_binfhe
OFHE=/home/ffx/fhe-project/deps/openfhe-install
SRC="$ROOT/binfhe_probe.cpp"

INC="-I$OFHE/include/openfhe -I$OFHE/include/openfhe/core -I$OFHE/include/openfhe/pke -I$OFHE/include/openfhe/binfhe"
LIBDIR="-L$OFHE/lib"
LIBS="-lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp"

mkdir -p "$ROOT/build_plain" "$ROOT/build_asan"

echo "=== [1/2] plain build (-O1 -g) ==="
g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 \
    $INC "$SRC" -o "$ROOT/build_plain/binfhe_probe" $LIBDIR $LIBS

echo "=== [2/2] sanitized build (-fsanitize=address,undefined) ==="
g++ -std=c++17 -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 \
    $INC "$SRC" -o "$ROOT/build_asan/binfhe_probe" $LIBDIR $LIBS

echo "=== done ==="
ls -la "$ROOT/build_plain/binfhe_probe" "$ROOT/build_asan/binfhe_probe"
