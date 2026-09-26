// repro_evalsign_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: EvalSign() with a null ciphertext.
// CVE-2025-28183 class.
// Observed: SIGSEGV reading null+0x28 in BinFHEScheme::EvalSign ->
// binfhe-base-scheme.cpp:315 `auto mod = ct->GetModulus();` (no null check).
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evalsign_null_ct.cpp -o repro_evalsign_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evalsign_null_ct
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);   // EvalSign needs an initialised context
    LWECiphertext null_ct;
    std::cout << "calling EvalSign(null)" << std::endl;
    (void)cc.EvalSign(null_ct);            // <-- SIGSEGV (no keys needed)
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
