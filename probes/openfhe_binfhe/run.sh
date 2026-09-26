#!/bin/bash
# Run both probe binaries and capture full output.
set -u
ROOT=/home/ffx/fuzz-lab2/fhe_fuzz/probes/openfhe_binfhe
export LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib

echo "### plain: $ROOT/run_plain.log"
"$ROOT/build_plain/binfhe_probe" > "$ROOT/run_plain.log" 2>&1

echo "### asan: $ROOT/run_asan.log"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 UBSAN_OPTIONS=print_stacktrace=1 \
  "$ROOT/build_asan/binfhe_probe" > "$ROOT/run_asan.log" 2>&1
echo done
