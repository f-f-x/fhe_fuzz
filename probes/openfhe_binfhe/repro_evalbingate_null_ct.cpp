// repro_evalbingate_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: EvalBinGate() with a null ct.
// CVE-2025-28187 class.
// Observed: SIGSEGV reading null+0x10 (NativeVectorT::operator=) in
// LWEEncryptionScheme::EvalAddEq, reached from BinFHEScheme::EvalBinGate ->
// binfhe-base-scheme.cpp:76 `std::make_shared<LWECiphertextImpl>(*ct1)` (no null check).
// NOTE: EvalBinGate(AND, null, null) does NOT crash -- it throws config_error at
// line 61 because `ct1 == ct2` compares the shared_ptr values first.
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evalbingate_null_ct.cpp -o repro_evalbingate_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evalbingate_null_ct
#include "binfhecontext.h"
#include <exception>
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto ct = cc.Encrypt(sk, 1, FRESH);
    LWECiphertext null_ct;
    std::cout << "baseline EvalBinGate ok" << std::endl;
    try {
        (void)cc.EvalBinGate(AND, ct, ct);      // throws config_error (ct1 == ct2)
    } catch (const std::exception& e) {
        std::cout << "ct1==ct2 -> " << e.what() << std::endl;
    }
    (void)cc.EvalBinGate(AND, null_ct, ct);     // <-- SIGSEGV
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
