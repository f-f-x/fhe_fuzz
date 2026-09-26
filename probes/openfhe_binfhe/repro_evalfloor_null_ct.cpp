// repro_evalfloor_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: EvalFloor() with a null ciphertext.
// CVE-2025-28188 class.
// Observed: SIGSEGV reading null+0x28 in BinFHEScheme::EvalFloor ->
// binfhe-base-scheme.cpp:276 `NativeInteger mod = ct->GetModulus();` (no null check).
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evalfloor_null_ct.cpp -o repro_evalfloor_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evalfloor_null_ct
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto ct = cc.Encrypt(sk, 1, FRESH);
    std::cout << "baseline EvalFloor ok" << std::endl;
    (void)cc.EvalFloor(ct, 0);
    LWECiphertext null_ct;
    (void)cc.EvalFloor(null_ct, 0);     // <-- SIGSEGV
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
