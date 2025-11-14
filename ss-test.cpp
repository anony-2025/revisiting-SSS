#include "openfhe.h"
#include <omp.h>

using namespace lbcrypto;

void PrintDCRTPoly(const DCRTPoly& poly, const std::string& name) {
    DCRTPoly temp = poly;
    if (temp.GetFormat() == Format::EVALUATION)
        temp.SwitchFormat();  // NTT domain → coefficient domain

    std::cout << "==== " << name << " ====" << std::endl;
    auto towers = temp.GetAllElements();

    for (size_t i = 0; i < towers.size(); i++) {
        std::cout << "  Tower " << i 
                  << " (modulus = " << towers[i].GetModulus() << ")" << std::endl;

        auto vals = towers[i].GetValues();  
        size_t len = vals.GetLength();   

        for (size_t j = 0; j < std::min<size_t>(len, 32); j++)
            std::cout << vals[j] << " ";
        if (len > 32)
            std::cout << "...";
        std::cout << std::endl;
    }
    std::cout << std::endl;
}


void PrintContextModuli(const CryptoContext<DCRTPoly>& cc, const std::string& name) {
    std::cout << "==== Context Moduli (" << name << ") ====\n";

    // --- Q-chain ---
    auto qParams = cc->GetCryptoParameters()->GetElementParams();
    if (qParams) {
        const auto& qTowers = qParams->GetParams();
        std::cout << "Q-chain (" << qTowers.size() << " primes): ";
        double sumQ = 0.0;
        for (size_t i = 0; i < qTowers.size(); ++i) {
            auto qi = qTowers[i]->GetModulus();
            double bits = qi.GetMSB();
            sumQ += bits;
            std::cout << bits << " ";
        }
        std::cout << "(sum = " << sumQ << " bits)\n";
    }

    // --- P-chain ---
    auto base = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    if (base && base->GetParamsP()) {
        const auto& pTowers = base->GetParamsP()->GetParams();
        std::cout << "P-chain (" << pTowers.size() << " primes): ";
        double sumP = 0.0;
        for (size_t i = 0; i < pTowers.size(); ++i) {
            auto pi = pTowers[i]->GetModulus();
            double bits = pi.GetMSB();
            sumP += bits;
            std::cout << bits << " ";
        }
        std::cout << "(sum = " << sumP << " bits)\n";
    }

    std::cout << std::endl;
}

void PrintCiphertextModuli(const Ciphertext<DCRTPoly>& ct, const std::string& name) {
    if (!ct) {
        std::cout << "Ciphertext " << name << " is null.\n";
        return;
    }

    std::cout << "==== Ciphertext Moduli (" << name << ") ====\n";
    const auto& cv = ct->GetElements();

    for (size_t idx = 0; idx < cv.size(); ++idx) {
        auto& poly = cv[idx];
        auto params = poly.GetParams()->GetParams();
        std::cout << "  Component c" << idx
                  << ": " << params.size() << " towers" << std::endl;
        double sumBits = 0.0;
        for (size_t i = 0; i < params.size(); ++i) {
            auto qi = params[i]->GetModulus();
            double bits = qi.GetMSB();
            sumBits += bits;
            std::cout << "    q_" << i << " ≈ " << bits << " bits" << std::endl;
        }
        std::cout << "    Total log2(Q) ≈ " << sumBits << " bits\n";
    }
    std::cout << std::endl;
}

// Single-switch BFV test for 2adic / shamir / BFM+25
void BFVTest() {
    // ======= Change this one variable to switch the scheme =======
    const std::string SHARE_TYPE = "2adic"; // "2adic", "shamir", "BFM+25"
    // =============================================================

    const usint N       = 128;
    const usint THRESH  = 5;
    const int trials    = 128;

    // NOISE_FLOODING_MULTIPARTY or FIXED_NOISE_MULTIPARTY
    MultipartyMode decryptMode = FIXED_NOISE_MULTIPARTY;

    auto buildContext = [&]() {
        CCParams<CryptoContextBFVRNS> p;
        p.SetMultiplicativeDepth(1);
        p.SetScalingModSize(42);
        p.SetPlaintextModulus(2);
        p.SetSecurityLevel(HEStd_128_classic);
        p.SetMultipartyMode(decryptMode);
        p.SetThresholdNumOfParties(N);
        return CryptoContextBFVRNS::genCryptoContext(p);
    };

    auto cc = buildContext();
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);
    cc->Enable(MULTIPARTY);

    std::cout << "Using SHARE_TYPE       : " << SHARE_TYPE << "\n";
    std::cout << "Using decrypt mode     : " << decryptMode << "\n";
    std::cout << "Using ring dimension   : " << cc->GetRingDimension() << "\n";
    PrintContextModuli(cc, "BFV fresh (" + SHARE_TYPE + ")");

    auto DumpPT = [](const std::string& tag, const Plaintext& pt) {
        std::cout << "  " << tag
                  << " len=" << pt->GetLength() << " values: ";
        const auto& v = pt->GetCoefPackedValue();
        size_t show = std::min<size_t>(v.size(), 8);
        for (size_t i = 0; i < show; ++i) std::cout << v[i] << " ";
        if (v.size() > show) std::cout << "...";
        std::cout << "\n";
    };

    int okCountDecrypt = 0;
    int okCountFusion  = 0;

#pragma omp parallel for reduction(+:okCountDecrypt,okCountFusion) schedule(dynamic)
    for (int t = 1; t <= trials; ++t) {
        // RNG per-thread
        std::random_device rd;
        std::mt19937 gen(rd() + omp_get_thread_num());
        std::uniform_int_distribution<int> bitdist(0, 1);

        // Random 1-bit message
        std::vector<int64_t> msg = { static_cast<int64_t>(bitdist(gen)) };
        Plaintext pt = cc->MakeCoefPackedPlaintext(msg);

        // 1) Dealer keygen for the selected share type
        auto kp = cc->SpecialKeyGen(SHARE_TYPE, N, THRESH);

        // 2) Dealer produces N shares for threshold THRESH
        auto shares = cc->ShareKeysDealer(kp.secretKey, N, THRESH, SHARE_TYPE);

        // 3) Dealer reconstructs the secret key (full reconstruction path)
        PrivateKey<DCRTPoly> recKey = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
        cc->RecoverSharedKeyDealer(recKey, shares, N, THRESH, SHARE_TYPE);

        // 4) Encrypt under the public key
        Ciphertext<DCRTPoly> ct;
        if (SHARE_TYPE == "BFM+25") {
            // For BFM+25, use the specialized encryption method. Currently, it does not support
            ct = cc->Encrypt(kp.publicKey, pt);
            // ct = cc->BFMEncrypt(kp.publicKey, pt);
        } else {
            ct = cc->Encrypt(kp.publicKey, pt);
        }

        // 5) Check "Decrypt with reconstructed key"
        Plaintext dec;
        cc->Decrypt(recKey, ct, &dec);

        auto expected = cc->MakeCoefPackedPlaintext(msg);
        expected->SetLength(8);
        dec->SetLength(8);

        bool okDec = (*dec == *expected);
        if (okDec) okCountDecrypt++;

        // 6) Randomly sample exactly THRESH party IDs for partial decryption (from the outset)
        std::vector<uint32_t> all_ids(N);
        std::iota(all_ids.begin(), all_ids.end(), 1);
        std::vector<uint32_t> use_ids;
        use_ids.reserve(THRESH);
        std::sample(all_ids.begin(), all_ids.end(), std::back_inserter(use_ids), THRESH, gen);
        std::sort(use_ids.begin(), use_ids.end());

        // 7) Generate partial decryptions ONLY for the sampled t IDs
        std::unordered_map<uint32_t, Ciphertext<DCRTPoly>> partials;
        partials.reserve(use_ids.size());
        for (auto pid : use_ids) {
            auto sk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
            DCRTPoly s = shares.at(pid);
            s.SetFormat(Format::EVALUATION);
            sk->SetPrivateElement(s);

            auto part = cc->GenPartialDec(ct, sk, /*denomClear=*/true, SHARE_TYPE, N, THRESH);
            partials.emplace(pid, part);
        }

        // 8) Fusion over the sampled subset
        Plaintext fused;
        cc->MultipartyDecryptFusionDistributed(ct, partials, THRESH, &fused,
                                               SHARE_TYPE, /*denomClear=*/false, N);
        fused->SetLength(8);
        bool okFused = (*fused == *expected);
        if (okFused) okCountFusion++;

#pragma omp critical
        {
            std::cout << "\n[Trial " << t << "] SHARE_TYPE=" << SHARE_TYPE
                      << "  msg=" << msg[0] << "\n";

            std::cout << "[Check] Decrypt(reconstructed key): "
                      << (okDec ? "OK" : "MISMATCH") << "\n";
            DumpPT("expected", expected);
            DumpPT("got     ", dec);
            std::cout << "\n";

            std::cout << "Fusion(" << SHARE_TYPE << ", subset: ";
            for (auto id : use_ids) std::cout << id << " ";
            std::cout << "): " << (okFused ? "OK" : "MISMATCH") << "\n";
            DumpPT("expected", expected);
            DumpPT("got     ", fused);
            std::cout << std::endl;
        }
    }

    std::cout << "===========================================\n";
    std::cout << "Summary (" << SHARE_TYPE << "):\n";
    std::cout << "  OK count (decrypt via reconstructed key): "
              << okCountDecrypt << " / " << trials << "\n";
    std::cout << "  OK count (fusion over t partials)       : "
              << okCountFusion  << " / " << trials << "\n";
    std::cout << "===========================================\n";
}


int main() {
    BFVTest();
    return 0;
}
