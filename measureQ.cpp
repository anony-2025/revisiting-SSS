#include "openfhe.h"
#include <random>
#include <fstream>
#include <numeric>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <complex>
#include <cmath>

#ifdef _OPENMP
#include <omp.h>
#endif

using namespace lbcrypto;

// ---------------------------------------------------------------------------
// Parameter structure (per (N,t) pair)
// ---------------------------------------------------------------------------
struct ParamNT {
    uint32_t N;
    uint32_t t;
    uint32_t ringDim;
    uint32_t scaleModSize;
    uint32_t multDepth;
};

// ---------------------------------------------------------------------------
// Centered coefficient bit-length
// ---------------------------------------------------------------------------
static uint32_t MaxCenteredCoeffBitLen(const DCRTPoly& poly) {
    DCRTPoly tmp = poly;
    if (tmp.GetFormat() != Format::COEFFICIENT)
        tmp.SetFormat(Format::COEFFICIENT);

    auto bigPoly = tmp.CRTInterpolate();
    BigInteger Q = bigPoly.GetParams()->GetModulus();
    BigInteger half = Q >> 1;

    uint32_t maxBits = 0;
    for (usint i = 0; i < bigPoly.GetLength(); ++i) {
        BigInteger c = bigPoly[i];
        if (c > half)
            c = Q - c;
        uint32_t bits = (c == 0u) ? 0u : (uint32_t)c.GetMSB();
        if (bits > maxBits)
            maxBits = bits;
    }
    return maxBits;
}

// ---------------------------------------------------------------------------
// Canonical embedding sup-norm (log2 scale, power-of-two cyclotomic)
// σ_j(f) = f(ζ_j), ζ_j = exp(iπ(2j+1)/n), j = 0..n-1
// ---------------------------------------------------------------------------
static double CanonLog2SupNorm(const DCRTPoly& poly) {
    DCRTPoly tmp = poly;
    if (tmp.GetFormat() != Format::COEFFICIENT)
        tmp.SetFormat(Format::COEFFICIENT);

    auto bigPoly = tmp.CRTInterpolate();
    BigInteger Q   = bigPoly.GetParams()->GetModulus();
    BigInteger half = Q >> 1;

    const usint n = bigPoly.GetLength();
    if (n == 0)
        return 0.0;

    // Centered integer coefficients as long double
    std::vector<long double> coeffs(n);
    for (usint i = 0; i < n; ++i) {
        BigInteger c = bigPoly[i];
        if (c > half)
            c = Q - c;
        coeffs[i] = static_cast<long double>(c.ConvertToDouble());
    }

    const long double PI = acosl(-1.0L);
    long double maxVal = 0.0L;

    // Canonical embeddings at ζ_j = exp(iπ(2j+1)/n)
    for (usint j = 0; j < n; ++j) {
        long double theta = PI * ((long double)(2 * j + 1) / (long double)n);
        long double cos_t = cosl(theta);
        long double sin_t = sinl(theta);

        long double xr = 1.0L, xi = 0.0L;  // ζ_j^0
        long double sumr = 0.0L, sumi = 0.0L;

        // f(ζ_j) = ∑ a_k ζ_j^k
        for (usint k = 0; k < n; ++k) {
            long double a = coeffs[k];
            sumr += a * xr;
            sumi += a * xi;

            long double nr = xr * cos_t - xi * sin_t;
            long double ni = xr * sin_t + xi * cos_t;
            xr = nr;
            xi = ni;
        }

        long double absval = sqrtl(sumr * sumr + sumi * sumi);
        if (absval > maxVal)
            maxVal = absval;
    }

    if (maxVal <= 0.0L)
        return 0.0;

    // 필요하면 여기서 maxVal /= sqrtl((long double)n); 로 정규화도 가능
    return std::log2((double)maxVal);
}

// ===========================================================================
// 2-ADIC FUNCTIONS
// ===========================================================================

static DCRTPoly TwoAdic_MakeAlpha(uint32_t pid,
                                  const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
                                  uint32_t N) {
    const usint n = params->GetRingDimension();

    uint64_t M = 1;
    while (M < (uint64_t)N)
        M <<= 1;

    const uint64_t two_n = 2ULL * (uint64_t)n;
    const uint64_t h = two_n / M;

    unsigned __int128 sigma = (unsigned __int128)h * (unsigned __int128)pid;
    uint64_t r = (uint64_t)(sigma % n);
    bool negWrap = ((sigma / n) & 1) != 0;

    DCRTPoly alpha(params, Format::COEFFICIENT, true);
    const size_t K = params->GetParams().size();

    for (size_t k = 0; k < K; ++k) {
        auto pk = params->GetParams()[k];
        auto qk = pk->GetModulus();
        NativePoly mono(pk, Format::COEFFICIENT, true);
        mono[r] = negWrap ? (qk - 1) : NativeInteger(1);
        alpha.SetElementAtIndex(k, std::move(mono));
    }
    return alpha;
}

static std::vector<DCRTPoly> TwoAdic_BuildLjsAtMinus1(
    const std::vector<DCRTPoly>& alphas,
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {

    const size_t L = alphas.size();
    std::vector<DCRTPoly> Ljs;
    Ljs.reserve(L);

    // x0 = -1
    DCRTPoly minusOne(params, Format::COEFFICIENT, true);
    for (size_t k = 0; k < params->GetParams().size(); ++k) {
        auto pk = params->GetParams()[k];
        auto qk = pk->GetModulus();
        NativePoly c(pk, Format::COEFFICIENT, true);
        c[0] = qk - NativeInteger(1);
        minusOne.SetElementAtIndex(k, std::move(c));
    }

    // Evaluate alphas in EVALUATION form (for denom)
    std::vector<DCRTPoly> alEval(L);
    for (size_t j = 0; j < L; ++j) {
        alEval[j] = alphas[j];
        alEval[j].SetFormat(Format::EVALUATION);
    }

    for (size_t j = 0; j < L; ++j) {
        // Numerator / Denominator initialization
        DCRTPoly Numer(params, Format::COEFFICIENT, true);
        DCRTPoly Denom(params, Format::COEFFICIENT, true);

        for (size_t k = 0; k < params->GetParams().size(); ++k) {
            auto pk = params->GetParams()[k];
            NativePoly one(pk, Format::COEFFICIENT, true);
            one[0] = 1;
            Numer.SetElementAtIndex(k, one);
            Denom.SetElementAtIndex(k, one);
        }

        Numer.SetFormat(Format::EVALUATION);
        Denom.SetFormat(Format::EVALUATION);

        // Build L_j(-1) = ∏_{i≠j} (x0 - α_i)/(α_j - α_i)
        for (size_t i = 0; i < L; ++i) {
            if (i == j)
                continue;

            DCRTPoly x0MinusAlphaI = minusOne - alphas[i];
            x0MinusAlphaI.SetFormat(Format::EVALUATION);

            DCRTPoly denom = alEval[j].Minus(alEval[i]);

            Numer *= x0MinusAlphaI;
            Denom *= denom;
        }

        // Denominator inversion tower-wise
        DCRTPoly DenInv(params, Format::EVALUATION, true);
        for (size_t k = 0; k < params->GetParams().size(); ++k) {
            auto pk = params->GetParams()[k];
            auto qk = pk->GetModulus();
            const auto& den_k = Denom.GetElementAtIndex(k);
            auto vals = den_k.GetValues();
            usint len = vals.GetLength();
            NativeVector invVals(len, qk);
            for (usint s = 0; s < len; ++s)
                invVals[s] = vals[s].ModInverse(qk);
            NativePoly invPoly(pk, Format::EVALUATION, true);
            invPoly.SetValues(std::move(invVals), Format::EVALUATION);
            DenInv.SetElementAtIndex(k, std::move(invPoly));
        }

        DCRTPoly Lj = Numer * DenInv;
        Lj.SetFormat(Format::COEFFICIENT);
        Ljs.emplace_back(std::move(Lj));
    }
    return Ljs;
}

static void TwoAdic_MulByDelta(DCRTPoly& poly, uint32_t t) {
    if (poly.GetFormat() != Format::COEFFICIENT)
        poly.SetFormat(Format::COEFFICIENT);

    uint64_t exp = (uint64_t)std::ceil(std::log2((double)t));
    auto ep = poly.GetParams();

    for (size_t k = 0; k < ep->GetParams().size(); ++k) {
        auto qk = ep->GetParams()[k]->GetModulus();
        NativeInteger scale = NativeInteger(2).ModExp(NativeInteger(exp), qk);

        const auto& src = poly.GetElementAtIndex(k);
        NativePoly out(ep->GetParams()[k], Format::COEFFICIENT, true);
        for (usint i = 0; i < src.GetLength(); ++i)
            out[i] = src[i].ModMul(scale, qk);

        poly.SetElementAtIndex(k, std::move(out));
    }
}

static uint32_t TwoAdic_Trial(
    const std::vector<uint32_t>& subset,
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
    uint32_t N, uint32_t t,
    double& embBitsOut) {

    std::vector<DCRTPoly> alphas;
    for (auto pid : subset)
        alphas.emplace_back(TwoAdic_MakeAlpha(pid, params, N));

    auto Ljs = TwoAdic_BuildLjsAtMinus1(alphas, params);

    DCRTPoly S(params, Format::COEFFICIENT, true);
    for (auto& Lj : Ljs)
        S += Lj;

    // delta (denominator clearing) for 2-adic bound
    TwoAdic_MulByDelta(S, t);

    embBitsOut = CanonLog2SupNorm(S);
    return MaxCenteredCoeffBitLen(S);
}

// ===========================================================================
// BFM+25 FUNCTIONS
// ===========================================================================

static DCRTPoly BFM_MakeAlpha(uint32_t pid,
                              const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {
    const usint n = params->GetRingDimension();
    const uint32_t idx = pid - 1;
    const uint32_t iBit = (idx & 1u);
    const uint64_t jExp = (uint64_t)(idx >> 1);
    const size_t r = (size_t)(jExp % n);

    DCRTPoly alpha(params, Format::COEFFICIENT, true);
    const size_t K = params->GetParams().size();

    for (size_t k = 0; k < K; ++k) {
        auto pk = params->GetParams()[k];
        auto qk = pk->GetModulus();
        NativePoly mono(pk, Format::COEFFICIENT, true);
        mono[r] = iBit ? (qk - 1) : NativeInteger(1);
        alpha.SetElementAtIndex(k, std::move(mono));
    }
    return alpha;
}

static std::vector<DCRTPoly> BFM_BuildLjsAt0(
    const std::vector<DCRTPoly>& alphas,
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {

    const size_t L = alphas.size();
    std::vector<DCRTPoly> Ljs;
    Ljs.reserve(L);

    // Evaluate alphas in EVALUATION (for denominators)
    std::vector<DCRTPoly> alEval(L);
    for (size_t j = 0; j < L; ++j) {
        alEval[j] = alphas[j];
        alEval[j].SetFormat(Format::EVALUATION);
    }

    for (size_t j = 0; j < L; ++j) {
        DCRTPoly Lj(params, Format::COEFFICIENT, true);
        for (size_t k = 0; k < params->GetParams().size(); ++k) {
            auto pk = params->GetParams()[k];
            NativePoly one(pk, Format::COEFFICIENT, true);
            one[0] = 1;
            Lj.SetElementAtIndex(k, std::move(one));
        }
        Lj.SetFormat(Format::EVALUATION);

        // L_j(0) = ∏_{i≠j} (-α_i)/(α_j - α_i)
        for (size_t i = 0; i < L; ++i) {
            if (i == j)
                continue;

            DCRTPoly negAlphaI = alEval[i].Negate();
            DCRTPoly denom = alEval[j].Minus(alEval[i]);

            // Invert denom tower-wise
            DCRTPoly denomInv(params, Format::EVALUATION, true);
            for (size_t k = 0; k < params->GetParams().size(); ++k) {
                auto pk = params->GetParams()[k];
                auto qk = pk->GetModulus();
                const auto& den_k = denom.GetElementAtIndex(k);
                auto vals = den_k.GetValues();
                usint len = vals.GetLength();
                NativeVector invVals(len, qk);
                for (usint s = 0; s < len; ++s)
                    invVals[s] = vals[s].ModInverse(qk);
                NativePoly invPoly(pk, Format::EVALUATION, true);
                invPoly.SetValues(std::move(invVals), Format::EVALUATION);
                denomInv.SetElementAtIndex(k, std::move(invPoly));
            }

            Lj *= negAlphaI;
            Lj *= denomInv;
        }

        Lj.SetFormat(Format::COEFFICIENT);
        Ljs.emplace_back(std::move(Lj));
    }
    return Ljs;
}

static DCRTPoly BFM_BuildDelta(
    uint32_t N,
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {

    const usint Ndim = params->GetRingDimension();
    const size_t K = params->GetParams().size();

    DCRTPoly Delta(params, Format::COEFFICIENT, true);
    for (size_t k = 0; k < K; ++k) {
        auto pk = params->GetParams()[k];
        auto qk = pk->GetModulus();
        NativePoly c(pk, Format::COEFFICIENT, true);
        c[0] = NativeInteger(2) % qk;
        Delta.SetElementAtIndex(k, std::move(c));
    }
    Delta.SetFormat(Format::EVALUATION);

    auto mul_term = [&](usint deg) {
        DCRTPoly term(params, Format::COEFFICIENT, true);
        for (size_t k = 0; k < K; ++k) {
            auto pk = params->GetParams()[k];
            auto qk = pk->GetModulus();
            NativePoly poly(pk, Format::COEFFICIENT, true);

            bool wrapNeg = ((deg / Ndim) & 1u) != 0;
            usint r = deg % Ndim;
            poly[r] = wrapNeg ? (qk - NativeInteger(1)) : NativeInteger(1);
            poly[0] = qk - NativeInteger(1);  // X^0 coefficient = -1
            term.SetElementAtIndex(k, std::move(poly));
        }
        term.SetFormat(Format::EVALUATION);
        Delta *= term;
    };

    // Product ranges from BFM+25
    usint eMax1 = (usint)(N / 2);
    for (usint e = 1; e <= eMax1; ++e)
        mul_term(2 * e);

    usint eMax2 = (usint)(N / 6);
    for (usint e = 1; e <= eMax2; ++e)
        mul_term(2 * e);

    Delta.SetFormat(Format::COEFFICIENT);
    return Delta;
}

static uint32_t BFM_Trial(
    const std::vector<uint32_t>& subset,
    uint32_t N,
    const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
    double& embBitsOut) {

    std::vector<DCRTPoly> alphas;
    for (auto pid : subset)
        alphas.emplace_back(BFM_MakeAlpha(pid, params));

    auto Ljs = BFM_BuildLjsAt0(alphas, params);

    DCRTPoly S(params, Format::COEFFICIENT, true);
    for (auto& Lj : Ljs)
        S += Lj;

    // BFM Delta (denominator clearing)
    DCRTPoly Delta = BFM_BuildDelta(N, params);

    Delta.SetFormat(Format::EVALUATION);
    S.SetFormat(Format::EVALUATION);
    DCRTPoly DS = Delta * S;

    DS.SetFormat(Format::COEFFICIENT);

    embBitsOut = CanonLog2SupNorm(DS);
    return MaxCenteredCoeffBitLen(DS);
}

// ===========================================================================
// Experiment runner
// ===========================================================================

static void RunExperiments(
    const std::vector<ParamNT>& cfgs,
    uint32_t trials,
    const std::string& outPath) {

    std::ofstream ofs(outPath, std::ios::out | std::ios::trunc);
    if (!ofs)
        throw std::runtime_error("cannot open output file");

    ofs << "-----------------------------------------------------------------------------------------------------------------------------\n";
    ofs << " (N,t)  |      BFM+25 (coeff & embedding)                  |       2-adic (coeff & embedding)           \n";
    ofs << "        |  WorstC   AvgC    WorstEmb     AvgEmb            |  WorstC   AvgC    WorstEmb     AvgEmb      \n";
    ofs << "-----------------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& cfg : cfgs) {
        CCParams<CryptoContextBFVRNS> params;
        params.SetMultiplicativeDepth(cfg.multDepth);
        params.SetRingDim(cfg.ringDim);
        params.SetScalingModSize(cfg.scaleModSize);
        params.SetPlaintextModulus(2);
        params.SetSecurityLevel(HEStd_NotSet);
        params.SetMultipartyMode(FIXED_NOISE_MULTIPARTY);
        params.SetThresholdNumOfParties(cfg.N);

        auto cc = CryptoContextBFVRNS::genCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
        cc->Enable(KEYSWITCH);
        cc->Enable(MULTIPARTY);

        auto elementParams = cc->GetCryptoParameters()->GetElementParams();

        std::vector<uint32_t> allTemplate(cfg.N);
        std::iota(allTemplate.begin(), allTemplate.end(), 1u);

        double sumBFM = 0.0, sum2A = 0.0;
        double sumEmbBFM = 0.0, sumEmb2A = 0.0;

        uint32_t maxBFM = 0, max2A = 0;
        double maxEmbBFM = 0.0, maxEmb2A = 0.0;

        std::cout << "[*] Running N=" << cfg.N << ", t=" << cfg.t
                  << " (" << trials << " trials)..." << std::endl;

        #pragma omp parallel for reduction(+:sumBFM,sum2A,sumEmbBFM,sumEmb2A) \
                                 reduction(max:maxBFM,max2A)                  \
                                 reduction(max:maxEmbBFM,maxEmb2A)
        for (int rep = 0; rep < (int)trials; ++rep) {
            std::mt19937_64 rng_local(0xC0FFEEULL ^ (0x9E3779B97F4A7C15ULL * (uint64_t)rep));

            auto all = allTemplate;
            std::shuffle(all.begin(), all.end(), rng_local);
            std::vector<uint32_t> subset(all.begin(), all.begin() + cfg.t);
            std::sort(subset.begin(), subset.end());

            double embBFM = 0.0, emb2A = 0.0;

            uint32_t bitsBFM = BFM_Trial(subset, cfg.N, elementParams, embBFM);
            uint32_t bits2A  = TwoAdic_Trial(subset, elementParams, cfg.N, cfg.t, emb2A);

            sumBFM += bitsBFM;
            sum2A  += bits2A;
            sumEmbBFM += embBFM;
            sumEmb2A  += emb2A;

            if (bitsBFM > maxBFM) maxBFM = bitsBFM;
            if (bits2A  > max2A)  max2A  = bits2A;
            if (embBFM > maxEmbBFM) maxEmbBFM = embBFM;
            if (emb2A  > maxEmb2A)  maxEmb2A  = emb2A;

        #ifdef _OPENMP
            if (omp_get_thread_num() == 0 && rep % (trials/5 + 1) == 0) {
                std::cout << "    progress: " << rep << "/" << trials << " trials\r" << std::flush;
            }
        #endif
        }

        double avgBFM = sumBFM / trials;
        double avg2A  = sum2A  / trials;
        double avgEmbBFM = sumEmbBFM / trials;
        double avgEmb2A  = sumEmb2A  / trials;

        std::cout << "    done. "
                  << "BFM coeff(avg=" << avgBFM << ", max=" << maxBFM << "), "
                  << "emb(avg=" << avgEmbBFM << ", max=" << maxEmbBFM << "); "
                  << "2adic coeff(avg=" << avg2A << ", max=" << max2A << "), "
                  << "emb(avg=" << avgEmb2A << ", max=" << maxEmb2A << ")"
                  << std::endl;

        ofs << " (" << std::setw(3) << cfg.N << "," << std::setw(3) << cfg.t << ") | "
            << std::setw(7) << maxBFM      << " " << std::setw(8) << avgBFM
            << "   " << std::setw(10) << maxEmbBFM << " " << std::setw(10) << avgEmbBFM << " | "
            << std::setw(7) << max2A       << " " << std::setw(8) << avg2A
            << "   " << std::setw(10) << maxEmb2A  << " " << std::setw(10) << avgEmb2A
            << "\n";
    }

    ofs << "-----------------------------------------------------------------------------------------------------------------------------\n";
    ofs.close();
}

// ===========================================================================
// Main driver
// ===========================================================================

int main() {
    std::vector<ParamNT> cfgs = {
        {32, 5, 8192, 50, 3},
        {32, 10, 8192, 50, 3},
        {32, 16, 8192, 50, 3},
        {32, 21, 8192, 50, 3},

        {64, 5, 8192, 50, 3},
        {64, 6, 8192, 50, 3},
        {64, 21, 8192, 50, 3},
        {64, 32, 8192, 50, 3},
        {64, 42, 8192, 50, 3},

        {128, 5, 8192, 50, 3},
        {128, 7, 8192, 50, 3},
        {128, 42, 8192, 50, 3},
        {128, 64, 8192, 50, 3},
        {128, 85, 8192, 50, 3},

        {256, 5, 8192, 50, 3},
        {256, 8, 8192, 50, 3},
        {256, 85, 8192, 50, 3},
        {256, 128, 8192, 50, 3},
        {256, 170, 8192, 50, 3},

        {512, 5, 8192, 50, 3},
        {512, 9, 8192, 50, 3},
        {512, 170, 8192, 50, 3},
        {512, 256, 8192, 50, 3},
        {512, 341, 8192, 50, 3},
    };

    RunExperiments(cfgs, 10, "delta_sumL_results.txt");
    return 0;
}
