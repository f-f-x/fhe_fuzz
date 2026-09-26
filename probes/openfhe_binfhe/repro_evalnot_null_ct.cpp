// repro_evalnot_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: EvalNOT() with a null ciphertext.
// CVE-2025-28185 class.
// Observed: SIGSEGV reading null+0x28 in BinFHEScheme::EvalNOT ->
// binfhe-base-scheme.cpp:148 `NativeInteger q = ct->GetModulus();` (no null check).
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evalnot_null_ct.cpp -o repro_evalnot_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evalnot_null_ct
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    auto ct = cc.Encrypt(sk, 1, FRESH);
    std::cout << "baseline EvalNOT ok" << std::endl;
    (void)cc.EvalNOT(ct);
    LWECiphertext null_ct;
    (void)cc.EvalNOT(null_ct);          // <-- SIGSEGV (no keys needed)
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
