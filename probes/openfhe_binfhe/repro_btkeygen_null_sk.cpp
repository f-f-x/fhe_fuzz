// repro_btkeygen_null_sk.cpp -- OpenFHE 1.0.4 BINFHE: BTKeyGen() with a null secret key.
// CVE-2025-28184 class.
// Observed: SIGSEGV reading null+0x28 in BinFHEScheme::KeyGen ->
// binfhe-base-scheme.cpp:44 `LWEscheme->KeySwitchGen(LWEParams, LWEsk, skN)` ->
// lwe-pke.cpp:198 `NativeVector sv = sk->GetElement();` (no null check).
// IMPORTANT: the null sk is only dereferenced when the context has no cached
// Bootstrapping key map yet. BinFHEContext::BTKeyGen (binfhecontext.cpp:216-238)
// only calls BinFHEScheme::KeyGen when `m_BTKey_map.size() == 0`; on a second
// call it reuses the cached key and ignores the (null) sk entirely. Hence the
// null-sk call below is made on a FRESH context.
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_btkeygen_null_sk.cpp -o repro_btkeygen_null_sk -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_btkeygen_null_sk
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    std::cout << "baseline BTKeyGen ok" << std::endl;
    LWEPrivateKey null_sk;              // empty shared_ptr == null pointer
    BinFHEContext cc2;                  // fresh context: no cached BT key map
    cc2.GenerateBinFHEContext(TOY, GINX);
    cc2.BTKeyGen(null_sk);              // <-- SIGSEGV
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
