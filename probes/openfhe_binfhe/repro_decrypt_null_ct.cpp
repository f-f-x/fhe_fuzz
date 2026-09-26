// repro_decrypt_null_ct.cpp -- OpenFHE 1.0.4 BINFHE: Decrypt() with a null ciphertext.
// CVE-2025-28182 class ("missing null pointer validation").
// Observed: SIGSEGV reading null+0x28 (NativeVectorT copy ctor on
// LWEPrivateKeyImpl/LWECiphertextImpl's vector member) via
// LWEEncryptionScheme::Decrypt -> lwe-pke.cpp:97 `const NativeInteger& mod = ct->GetModulus();`
// REBUILD+RUN (single line):
//   g++ -std=c++17 -O1 -g -DOPENFHE_VERSION=1.0.4 -DMATHBACKEND=4 -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/core -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/pke -I/home/ffx/fhe-project/deps/openfhe-install/include/openfhe/binfhe repro_decrypt_null_ct.cpp -o repro_decrypt_null_ct -L/home/ffx/fhe-project/deps/openfhe-install/lib -lOPENFHEbinfhe -lOPENFHEpke -lOPENFHEcore -fopenmp && LD_LIBRARY_PATH=/home/ffx/fhe-project/deps/openfhe-install/lib ./repro_decrypt_null_ct
#include "binfhecontext.h"
#include <iostream>
using namespace lbcrypto;
int main() {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto ct = cc.Encrypt(sk, 1, FRESH);
    std::cout << "baseline decrypt ok" << std::endl;
    LWEPlaintext res = 0;
    LWECiphertext null_ct;              // empty shared_ptr == null pointer
    cc.Decrypt(sk, null_ct, &res);      // <-- SIGSEGV
    std::cout << "NOT REACHED" << std::endl;
    return 0;
}
