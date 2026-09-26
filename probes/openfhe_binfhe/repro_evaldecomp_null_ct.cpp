// repro_evaldecomp_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: EvalDecomp() with a null ct.
// CVE-2025-28186 class.
// Observed: SIGSEGV reading null+0x28 in BinFHEScheme::EvalDecomp ->
// binfhe-base-scheme.cpp:378 `auto mod = ct->GetModulus();` (no null check).
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evaldecomp_null_ct.cpp -o repro_evaldecomp_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evaldecomp_null_ct
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);   // EvalDecomp needs an initialised context
    LWECiphertext null_ct;
    std::cout << "calling EvalDecomp(null)" << std::endl;
    (void)cc.EvalDecomp(null_ct);          // <-- SIGSEGV (no keys needed)
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
