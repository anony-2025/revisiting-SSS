//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-pke.h"

#include <random>

namespace lbcrypto {

KeyPair<DCRTPoly> PKEBFVRNS::KeyGenInternal(CryptoContext<DCRTPoly> cc, bool makeSparse) const {
    KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());

    std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        elementParams = cryptoParams->GetParamsQr();
    }
    const std::shared_ptr<ParmType> paramsPK = cryptoParams->GetParamsPK();

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DugType dug;
    TugType tug;

    // Private Key Generation

    DCRTPoly s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = DCRTPoly(dgg, paramsPK, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            break;
    }

    // Public Key Generation

    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);
    DCRTPoly b(ns * e - a * s);

    usint sizeQ  = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});
    keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());

    return keyPair;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static std::vector<NativeInteger> MakeScalePerTower_2PowT(
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params, uint64_t T) {
    const size_t vecSize = params->GetParams().size();
    std::vector<NativeInteger> v(vecSize);
    for (size_t k = 0; k < vecSize; ++k) {
        auto qk = params->GetParams()[k]->GetModulus();
        v[k]    = NativeInteger(2).ModExp(NativeInteger(T), qk); // 2^{t-1} mod qk, T=t-1
    }
    return v;
}

static std::vector<NativeInteger> MakeScalePerTower_FactPow4(
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params, uint32_t N) {
    const size_t vecSize = params->GetParams().size();
    std::vector<NativeInteger> v(vecSize, NativeInteger(1));
    for (size_t k = 0; k < vecSize; ++k) {
        auto qk  = params->GetParams()[k]->GetModulus();
        NativeInteger acc(1);
        // acc = N! mod qk
        for (uint32_t t = 2; t <= N; ++t)
            acc = acc.ModMul(NativeInteger(t), qk);
        // acc4 = (N!)^4 mod qk
        NativeInteger acc4 = acc;
        acc4 = acc4.ModMul(acc, qk); // (N!)^2
        acc4 = acc4.ModMul(acc, qk); // (N!)^3
        acc4 = acc4.ModMul(acc, qk); // (N!)^4
        v[k] = acc4;
    }
    return v;
}

static DCRTPoly ScaleNoisePerTower(const DCRTPoly& noise,
                                   const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
                                   const std::vector<NativeInteger>& scalePerTower) {
    std::vector<NativePoly> scaled;
    scaled.reserve(noise.GetNumOfElements());
    for (usint k = 0; k < noise.GetNumOfElements(); ++k) {
        auto nk = noise.GetElementAtIndex(k);         // EVALUATION
        auto qk = params->GetParams()[k]->GetModulus();
        const auto s = scalePerTower[k];
        for (usint j = 0; j < nk.GetLength(); ++j)
            nk[j] = nk[j].ModMul(s, qk);
        scaled.emplace_back(std::move(nk));
    }
    return DCRTPoly(scaled);
}
static void PrintDCRTPoly(const DCRTPoly& poly, const std::string& name) {
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

        // Find maximum coefficient in balanced representation [-q/2, q/2)
        auto modulus = towers[i].GetModulus();
        uint64_t q = modulus.ConvertToInt<uint64_t>();
        uint64_t q_half = q / 2;
        
        int64_t maxAbsCoeff = 0;
        for (size_t j = 0; j < len; j++) {
            uint64_t val = vals[j].ConvertToInt<uint64_t>();
            int64_t balanced;
            
            if (val > q_half) {
                balanced = static_cast<int64_t>(val) - static_cast<int64_t>(q);
            } else {
                balanced = static_cast<int64_t>(val);
            }
            
            int64_t absVal = std::abs(balanced);
            if (absVal > maxAbsCoeff)
                maxAbsCoeff = absVal;
        }
        
        // Calculate bit length of maximum absolute value
        int bitLength = 0;
        if (maxAbsCoeff > 0) {
            bitLength = 64 - __builtin_clzll(static_cast<uint64_t>(maxAbsCoeff));
        }
        
        std::cout << "    Max |coefficient| (balanced): " << maxAbsCoeff 
                  << " (" << bitLength << " bits)" << std::endl;

        for (size_t j = 0; j < std::min<size_t>(len, 32); j++)
            std::cout << vals[j] << " ";
        if (len > 32)
            std::cout << "...";
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

KeyPair<DCRTPoly> PKEBFVRNS::KeyGenInternalSpecial(CryptoContext<DCRTPoly> cc,
                                                   const std::string& shareType,
                                                   usint N, usint Threshold) const {
    KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());

    std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        elementParams = cryptoParams->GetParamsQr();
    }
    const std::shared_ptr<ParmType> paramsPK = cryptoParams->GetParamsPK();

    const auto ns      = cryptoParams->GetNoiseScale();               // default 1
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DugType dug;
    TugType tug;

    // ===== Secret key s =====
    DCRTPoly s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = DCRTPoly(dgg, paramsPK, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            break;
    }

    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    // DCRTPoly a(paramsPK, Format::EVALUATION, true);
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);

    // e.SetFormat(Format::COEFFICIENT);
    // PrintDCRTPoly(e, "error in key generation");
    // e.SetFormat(Format::EVALUATION);

    DCRTPoly eScaled;
    if (shareType == "2adic") {
        auto scale2Pow = MakeScalePerTower_2PowT(paramsPK, static_cast<uint64_t>(Threshold-1));
        eScaled = ScaleNoisePerTower(e, paramsPK, scale2Pow);
        // PrintDCRTPoly(eScaled, "scaled error in key generation");
    }
    else if (shareType == "shamir") {
        auto scaleFact4 = MakeScalePerTower_FactPow4(paramsPK, static_cast<uint32_t>(N));
        eScaled = ScaleNoisePerTower(e, paramsPK, scaleFact4);
    }
    else if (shareType == "additive" ) {
        eScaled = e;
    }
    else if (shareType == "BFM+25") {
        // ------------------------------------------------------------
        // Build Δ inline (no external helper)
        // Δ = 2 * ∏_{e=1}^{⌊N/2⌋}(X^{2e}-1) * ∏_{e=1}^{⌊N/6⌋}(X^{2e}-1)
        // ------------------------------------------------------------
        const size_t vecSize = paramsPK->GetParams().size();
        const usint  Ndim    = paramsPK->GetRingDimension();

        DCRTPoly Delta(paramsPK, Format::COEFFICIENT, true);
        // Initialize with constant 2
        for (size_t k = 0; k < vecSize; ++k) {
            auto pk     = paramsPK->GetParams()[k];
            auto modq_k = pk->GetModulus();
            NativePoly two(pk, Format::COEFFICIENT, true);
            two[0] = NativeInteger(2) % modq_k;
            Delta.SetElementAtIndex(k, std::move(two));
        }
        Delta.SetFormat(Format::EVALUATION);

        auto mul_term = [&](usint deg) {
            DCRTPoly term(paramsPK, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = paramsPK->GetParams()[k];
                auto modq_k = pk->GetModulus();

                NativePoly poly(pk, Format::COEFFICIENT, true);
                poly[deg % Ndim] = NativeInteger(1);           // +X^{deg}
                poly[0]          = modq_k - NativeInteger(1);  // -1
                term.SetElementAtIndex(k, std::move(poly));
            }
            term.SetFormat(Format::EVALUATION);
            Delta *= term;
        };

        const usint eMax1 = static_cast<usint>(N / 2);
        for (usint e = 1; e <= eMax1; ++e)
            mul_term(2 * e);
        const usint eMax2 = static_cast<usint>(N / 6);
        for (usint e = 1; e <= eMax2; ++e)
            mul_term(2 * e);

        // Multiply the keygen error by Δ
        eScaled = e * Delta;
    }

    else {
        OPENFHE_THROW("SpecialKeyGen: unknown shareType = " + shareType);
    }

    // b = ns * eScaled - a * s
    DCRTPoly b(ns * eScaled - a * s);
    // a.SetFormat(Format::COEFFICIENT);
    // PrintDCRTPoly(a, "public key a in key generation");
    // a.SetFormat(Format::EVALUATION);
    // b.SetFormat(Format::COEFFICIENT);
    // PrintDCRTPoly(b, "public key b in key generation");
    // b.SetFormat(Format::EVALUATION);

    usint sizeQ  = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});
    keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());

    return keyPair;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////


Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt, const PrivateKey<DCRTPoly> privateKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const auto elementParams = cryptoParams->GetElementParams();
    size_t sizeQ             = elementParams->GetParams().size();

    auto encParams = ptxt.GetParams();
    size_t sizeP   = encParams->GetParams().size();

    // enables encoding of plaintexts using a smaller number of RNS limbs
    size_t level = sizeQ - sizeP;

    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        ptxt.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = ptxt.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        ptxt     = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    ptxt.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<std::vector<DCRTPoly>> ba = EncryptZeroCore(privateKey, encParams);

    NativeInteger NegQModt       = cryptoParams->GetNegQModt(level);
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(level);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }

    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    ptxt.SetFormat(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].SetFormat(Format::COEFFICIENT);
    (*ba)[1].SetFormat(Format::COEFFICIENT);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
        (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    }

    (*ba)[0].SetFormat(Format::EVALUATION);
    (*ba)[1].SetFormat(Format::EVALUATION);

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt, const PublicKey<DCRTPoly> publicKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(publicKey->GetCryptoParameters());

    const auto elementParams = cryptoParams->GetElementParams();
    size_t sizeQ             = elementParams->GetParams().size();

    auto encParams = ptxt.GetParams();
    size_t sizeP   = encParams->GetParams().size();

    // enables encoding of plaintexts using a smaller number of RNS limbs
    size_t level = sizeQ - sizeP;

    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        ptxt.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = ptxt.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        ptxt     = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    ptxt.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<std::vector<DCRTPoly>> ba = EncryptZeroCore(publicKey, encParams);

    NativeInteger NegQModt       = cryptoParams->GetNegQModt(level);
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(level);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }

    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    ptxt.SetFormat(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].SetFormat(Format::COEFFICIENT);
    (*ba)[1].SetFormat(Format::COEFFICIENT);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
        (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    }

    (*ba)[0].SetFormat(Format::EVALUATION);
    (*ba)[1].SetFormat(Format::EVALUATION);

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

DecryptResult PKEBFVRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                                 NativePoly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);

    size_t sizeQl = b.GetNumOfElements();

    const auto elementParams = cryptoParams->GetElementParams();
    size_t sizeQ             = elementParams->GetParams().size();

    // use RNS procedures only if the number of RNS limbs is the same as for fresh ciphertexts
    if (sizeQl == sizeQ) {
        b.SetFormat(Format::COEFFICIENT);
        if (cryptoParams->GetMultiplicationTechnique() == HPS ||
            cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ ||
            cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
            *plaintext =
                b.ScaleAndRound(cryptoParams->GetPlaintextModulus(), cryptoParams->GettQHatInvModqDivqModt(),
                                cryptoParams->GettQHatInvModqDivqModtPrecon(), cryptoParams->GettQHatInvModqBDivqModt(),
                                cryptoParams->GettQHatInvModqBDivqModtPrecon(), cryptoParams->GettQHatInvModqDivqFrac(),
                                cryptoParams->GettQHatInvModqBDivqFrac());
        }
        else {
            *plaintext = b.ScaleAndRound(
                cryptoParams->GetModuliQ(), cryptoParams->GetPlaintextModulus(), cryptoParams->Gettgamma(),
                cryptoParams->GettgammaQHatInvModq(), cryptoParams->GettgammaQHatInvModqPrecon(),
                cryptoParams->GetNegInvqModtgamma(), cryptoParams->GetNegInvqModtgammaPrecon());
        }
    }
    else {
        // for the case when compress was called, we automatically reduce the polynomial to 1 RNS limb
        size_t diffQl = sizeQ - sizeQl;
        size_t levels = sizeQl - 1;
        for (size_t l = 0; l < levels; ++l) {
            b.DropLastElementAndScale(cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
                                      cryptoParams->GetqlInvModq(diffQl + l));
        }

        b.SetFormat(Format::COEFFICIENT);

        const NativeInteger t = cryptoParams->GetPlaintextModulus();
        NativePoly element    = b.GetElementAtIndex(0);
        const NativeInteger q = element.GetModulus();
        element               = element.MultiplyAndRound(t, q);

        // Setting the root of unity to ONE as the calculation is expensive
        // It is assumed that no polynomial multiplications in evaluation
        // representation are performed after this
        element.SwitchModulus(t, 1, 0, 0);

        *plaintext = element;
    }

    return DecryptResult(plaintext->GetLength());
}

// ============================================================
// Added: BFM+25 ThFHE encryption algorithm (BFMEncrypt / EncryptZeroCoreBFM)
// ============================================================

static NativeInteger SampleSmallBalanced(int32_t B, const NativeInteger& q, std::mt19937& rng) {
    std::uniform_int_distribution<int32_t> dist(-B, B);
    int32_t x = dist(rng);
    if (x < 0)
        return q - NativeInteger(static_cast<uint64_t>(-x));
    else
        return NativeInteger(static_cast<uint64_t>(x));
}

static DCRTPoly GenSmallUniformDCRT(const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
                                    usint ringDim, int32_t B, std::mt19937& rng) {
    DCRTPoly out(params, Format::COEFFICIENT, true);
    const auto& towers = params->GetParams();
    for (size_t k = 0; k < towers.size(); ++k) {
        auto pk     = towers[k];
        auto modq_k = pk->GetModulus();
        NativePoly epk(pk, Format::COEFFICIENT, true);
        for (usint i = 0; i < ringDim; ++i)
            epk[i] = SampleSmallBalanced(B, modq_k, rng);
        out.SetElementAtIndex(k, std::move(epk));
    }
    out.SetFormat(Format::EVALUATION);
    return out;
}

std::shared_ptr<std::vector<DCRTPoly>> PKEBFVRNS::BFMEncryptZeroCore(const PublicKey<DCRTPoly> publicKey,
                                                                     const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(publicKey->GetCryptoParameters());
    const std::vector<DCRTPoly>& pk = publicKey->GetPublicElements();

    const std::shared_ptr<ParmType> elementParams =
        (params == nullptr) ? cryptoParams->GetElementParams() : params;
    const usint ringDim = elementParams->GetRingDimension();

    std::random_device rd;
    std::mt19937 rng(rd());
    const int32_t Bsmall = 1;

    DCRTPoly v  = GenSmallUniformDCRT(elementParams, ringDim, Bsmall, rng);
    DCRTPoly e0 = GenSmallUniformDCRT(elementParams, ringDim, Bsmall, rng);
    DCRTPoly e1 = GenSmallUniformDCRT(elementParams, ringDim, Bsmall, rng);
    const auto ns = cryptoParams->GetNoiseScale();

    PrintDCRTPoly(v, "bfm encryption: v");
    PrintDCRTPoly(e0, "bfm encryption: e0");
    PrintDCRTPoly(e1, "bfm encryption: e1");

    uint32_t sizeQ  = pk[0].GetParams()->GetParams().size();
    uint32_t sizeQl = elementParams->GetParams().size();

    DCRTPoly c0, c1;
    if (sizeQl != sizeQ) {
        DCRTPoly p0 = pk[0].Clone();
        DCRTPoly p1 = pk[1].Clone();
        uint32_t diffQl = sizeQ - sizeQl;
        p0.DropLastElements(diffQl);
        p1.DropLastElements(diffQl);
        c0 = p0 * v + ns * e0;
        c1 = p1 * v + ns * e1;
    }
    else {
        c0 = pk[0] * v + ns * e0;
        c1 = pk[1] * v + ns * e1;
    }

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>({std::move(c0), std::move(c1)}));
}

Ciphertext<DCRTPoly> PKEBFVRNS::BFMEncrypt(DCRTPoly ptxt, const PublicKey<DCRTPoly> publicKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(publicKey->GetCryptoParameters());

    const auto elementParams = cryptoParams->GetElementParams();
    size_t sizeQ             = elementParams->GetParams().size();

    auto encParams = ptxt.GetParams();
    size_t sizeP   = encParams->GetParams().size();

    size_t level = sizeQ - sizeP;

    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        ptxt.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = ptxt.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        ptxt     = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    ptxt.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<std::vector<DCRTPoly>> ba = BFMEncryptZeroCore(publicKey, encParams);

    NativeInteger NegQModt       = cryptoParams->GetNegQModt(level);
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(level);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }

    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    ptxt.SetFormat(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].SetFormat(Format::COEFFICIENT);
    (*ba)[1].SetFormat(Format::COEFFICIENT);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
        (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    }

    (*ba)[0].SetFormat(Format::EVALUATION);
    (*ba)[1].SetFormat(Format::EVALUATION);

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

// ============================================================
// End of BFM+25 ThFHE encryption algorithm
// ============================================================


}  // namespace lbcrypto
