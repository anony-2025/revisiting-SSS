#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "utils/serial.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <filesystem>

using namespace lbcrypto;
using namespace std;

// ============================================================
// Utility: Serialize and measure object size
// ============================================================
template <typename T>
double MeasureSizeKB(const T& obj) {
    std::ostringstream os;
    try {
        lbcrypto::Serial::Serialize(obj, os, lbcrypto::SerType::BINARY);
    } catch (const std::exception&) {
        return 0.0;
    }
    std::streampos pos = os.tellp();
    return (pos >= 0) ? static_cast<double>(pos) / 1024.0 : 0.0;
}


// ============================================================
// Parameter structure
// ============================================================
struct ParamKey {
    std::string shareType;
    MultipartyMode decryptMode;
    usint N;
    usint t;
    bool operator<(const ParamKey& other) const {
        if (shareType != other.shareType)
            return shareType < other.shareType;
        if (N != other.N)
            return N < other.N;
        return t < other.t;
    }
};

struct ParamVal {
    usint n;
    usint scaleModSize;
    usint multDepth;
    double qBits; // precomputed or derived log2|Q|
};

// ============================================================
// Parameter Table 
// ============================================================
std::map<ParamKey, ParamVal> paramTable = {

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 32, 5},   {4096, 32, 1, 64}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 32, 10},   {4096, 36, 1, 72}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 32, 16},   {4096, 40, 1, 80}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 32, 21},   {4096, 40, 1, 80}}, 

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 64, 5},   {4096, 34, 1, 68}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 64, 6},   {4096, 35, 1, 70}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 64, 21},   {4096, 50, 1, 100}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 64, 32},   {4096, 52, 1, 104}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 64, 42},   {4096, 51, 1, 102}}, 

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 128, 5},   {4096, 36, 1, 72}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 128, 7},   {4096, 41, 1, 82}},
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 128, 42},   {8192, 49, 3, 147}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 128, 64},   {8192, 53, 3, 159}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 128, 85},   {8192, 51, 3, 153}}, 

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 256, 5},   {4096, 40, 1, 80}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 256, 8},   {4096, 44, 1, 88}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 256, 85},   {16384, 50, 7, 250}},  
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 256, 128},   {16384, 53, 7, 265}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 256, 170},   {16384, 42, 8, 252}}, 

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 512, 5},   {4096, 40, 1, 80}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 512, 9},   {4096, 52, 1, 104}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 512, 170},   {32768, 56, 14, 448}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 512, 256},   {32768, 44, 15, 484}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 512, 341},   {32768, 57, 14, 456}}, 

    // {{"2adic", FIXED_NOISE_MULTIPARTY, 1024, 5},   {4096, 43, 1, 86}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 1024, 10},   {4096, 57, 1, 114}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 1024, 341},   {0, 0, 0, 848}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 1024, 512},   {0, 0, 0, 914}}, 
    // {{"2adic", FIXED_NOISE_MULTIPARTY, 1024, 682},   {0, 0, 0, 850}}, 
   

    // {{"shamir", FIXED_NOISE_MULTIPARTY, 32, 5},   {32768, 44, 17, 484}},
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 32, 10},   {32768, 44, 17, 484}},
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 32, 16},   {32768, 44, 17, 484}}, 
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 32, 21},   {32768, 44, 17, 484}},

    // {{"shamir", FIXED_NOISE_MULTIPARTY, 64, 5},   {65536, 40, 44, 1200}}, 
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 64, 6},   {65536, 40, 44, 1200}}, 
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 64, 21},   {65536, 40, 44, 1200}}, 
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 64, 32},   {65536, 40, 44, 1200}},
    // {{"shamir", FIXED_NOISE_MULTIPARTY, 64, 42},   {65536, 40, 44, 1200}}, 

    // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
}; 

// ============================================================
// Single experiment runner
// ============================================================
void RunExperiment(const ParamKey& key, const ParamVal& val, int trials = 100) {
    std::filesystem::create_directory("result");

    std::string fname = "result/result_" + key.shareType +
                        "_N" + std::to_string(key.N) +
                        "_t" + std::to_string(key.t) + ".txt";
    std::ofstream fout(fname);
    fout << std::fixed << std::setprecision(2);

    fout << "===========================================\n";
    fout << "Share type : " << key.shareType << "\n";
    fout << "N (# parties) = " << key.N << ", t (threshold) = " << key.t << "\n";
    fout << "n (ring dimension) = " << val.n << ", |Q| = " << val.qBits << " bits\n";
    fout << "Security level : 128-bit classical\n";
    fout << "Trials = " << trials << "\n";
    fout << "===========================================\n\n";

    double totalKeyGen = 0, totalShare = 0, totalEnc = 0;
    double totalPartDec = 0, totalFusion = 0;
    double keySize = 0, shareSize = 0, ctSize = 0, partSize = 0;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bitdist(0, 1);

    for (int i = 1; i <= trials; i++) {
        CCParams<CryptoContextBFVRNS> params;
        params.SetMultiplicativeDepth(val.multDepth);
        params.SetRingDim(val.n);
        params.SetScalingModSize(val.scaleModSize);
        params.SetPlaintextModulus(2);
        params.SetSecurityLevel(HEStd_128_classic);
        params.SetMultipartyMode(key.decryptMode);
        params.SetThresholdNumOfParties(key.N);

        auto cc = CryptoContextBFVRNS::genCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
        cc->Enable(KEYSWITCH);
        cc->Enable(MULTIPARTY);

        // ============================
        // 1. KeyGen
        // ============================
        auto t1 = chrono::high_resolution_clock::now();
        auto kp = cc->SpecialKeyGen(key.shareType, key.N, key.t);
        auto t2 = chrono::high_resolution_clock::now();
        totalKeyGen += chrono::duration<double, milli>(t2 - t1).count();
        keySize += MeasureSizeKB(kp.publicKey);

        // ============================
        // 2. Share generation
        // ============================
        t1 = chrono::high_resolution_clock::now();
        auto shares = cc->ShareKeysDealer(kp.secretKey, key.N, key.t, key.shareType);
        t2 = chrono::high_resolution_clock::now();
        totalShare += chrono::duration<double, milli>(t2 - t1).count();
        shareSize += MeasureSizeKB(shares.begin()->second);

        // ============================
        // 3. Encryption
        // ============================
        std::vector<int64_t> msg = {static_cast<int64_t>(bitdist(gen))};
        Plaintext pt = cc->MakeCoefPackedPlaintext(msg);
        t1 = chrono::high_resolution_clock::now();
        auto ct = cc->Encrypt(kp.publicKey, pt);
        t2 = chrono::high_resolution_clock::now();
        totalEnc += chrono::duration<double, milli>(t2 - t1).count();
        ctSize += MeasureSizeKB(ct);

        // ============================
        // 4. Partial Decryptions (t-party)
        // ============================
        std::vector<uint32_t> all_ids(key.N);
        std::iota(all_ids.begin(), all_ids.end(), 1);
        std::vector<uint32_t> selected_ids;
        std::sample(all_ids.begin(), all_ids.end(),
                    std::back_inserter(selected_ids),
                    key.t, std::mt19937{std::random_device{}()});

        std::unordered_map<uint32_t, Ciphertext<DCRTPoly>> partials;

        t1 = chrono::high_resolution_clock::now();
        for (auto pid : selected_ids) {
            auto sk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
            DCRTPoly s = shares.at(pid);
            s.SetFormat(Format::EVALUATION);
            sk->SetPrivateElement(s);

            auto part = cc->GenPartialDec(ct, sk, true, key.shareType, key.N, key.t);
            partials.emplace(pid, part);
        }
        t2 = chrono::high_resolution_clock::now();
        double elapsed_ms = chrono::duration<double, milli>(t2 - t1).count();
        totalPartDec += elapsed_ms;

        if (!partials.empty())
            partSize += MeasureSizeKB(partials.begin()->second);

        double perParty_ms = elapsed_ms / key.t;

        // ============================
        // 5. Fusion (combine t partials)
        // ============================
        Plaintext fused;
        t1 = chrono::high_resolution_clock::now();
        cc->MultipartyDecryptFusionDistributed(ct, partials, key.t, &fused, key.shareType, false, key.N);
        t2 = chrono::high_resolution_clock::now();
        double fusion_ms = chrono::duration<double, milli>(t2 - t1).count();
        totalFusion += fusion_ms;

        fused->SetLength(16);
        pt->SetLength(16);

        bool ok = (*fused == *pt);

        fout << "[Trial " << i << "] msg=" << msg[0]
             << " → " << (ok ? "OK" : "MISMATCH") << "\n";
        fout << "  PartialDec total: " << elapsed_ms << " ms ("
             << elapsed_ms / 1000.0 << " s), per-party: "
             << perParty_ms << " ms\n";
        fout << "  Fusion time: " << fusion_ms << " ms ("
             << fusion_ms / 1000.0 << " s)\n\n";
    }

    // ====================================================
    // Average results
    // ====================================================
    double avgKeyGen = totalKeyGen / trials;
    double avgShare = totalShare / trials;
    double avgEnc = totalEnc / trials;
    double avgPart = totalPartDec / trials;
    double avgFusion = totalFusion / trials;

    keySize /= trials;
    shareSize /= trials;
    ctSize /= trials;
    partSize /= trials;

    auto fmt_time = [](double ms) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << ms << " ms (" << ms / 1000.0 << " s)";
        return oss.str();
    };
    auto fmt_mem = [](double kb) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << kb << " KB (" << kb / 1024.0 << " MB)";
        return oss.str();
    };

    fout << "========== AVERAGE RESULTS ==========\n";
    fout << "KeyGen time        : " << fmt_time(avgKeyGen) << "\n";
    fout << "ShareGen time      : " << fmt_time(avgShare) << "\n";
    fout << "Encryption time    : " << fmt_time(avgEnc) << "\n";
    fout << "PartialDec time    : " << fmt_time(avgPart)
         << " (total for t=" << key.t << ")\n";
    fout << "Fusion time        : " << fmt_time(avgFusion) << "\n\n";

    fout << "Key size           : " << fmt_mem(keySize) << "\n";
    fout << "Share size         : " << fmt_mem(shareSize) << "\n";
    fout << "Ciphertext size    : " << fmt_mem(ctSize) << "\n";
    fout << "PartialDec size    : " << fmt_mem(partSize) << "\n";
    fout << "===========================================\n";

    fout.close();

    std::cout << "Finished experiment for "
              << key.shareType << " (N=" << key.N << ", t=" << key.t << ")\n"
              << "→ Results saved to " << fname << std::endl;
}


// ============================================================
// Main
// ============================================================
int main() {
    for (const auto& [key, val] : paramTable) {
        RunExperiment(key, val, 100);
    }
    return 0;
}
