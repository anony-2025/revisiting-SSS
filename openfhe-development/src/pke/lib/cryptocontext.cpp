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
  Control for encryption operations
 */

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "math/chebyshev.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "schemerns/rns-scheme.h"

namespace lbcrypto {

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>> CryptoContextImpl<Element>::s_evalMultKeyMap{};
template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>
    CryptoContextImpl<Element>::s_evalAutomorphismKeyMap{};

template <typename Element>
void CryptoContextImpl<Element>::SetKSTechniqueInScheme() {
    // check if the scheme is an RNS scheme
    auto schemeRNSPtr = std::dynamic_pointer_cast<SchemeRNS>(m_scheme);
    if (schemeRNSPtr == nullptr)
        OPENFHE_THROW("The scheme is not RNS-based");

    // check if the parameter object is RNS-based
    auto elPtr = std::dynamic_pointer_cast<const CryptoParametersRNS>(m_params);
    if (elPtr == nullptr)
        OPENFHE_THROW("The parameter object is not RNS-based");

    schemeRNSPtr->SetKeySwitchingTechnique(elPtr->GetKeySwitchTechnique());
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////
template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeyGen(const PrivateKey<Element>& key) {
    ValidateKey(key);
    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(key->GetKeyTag()) ==
        CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // the key is not found in the map, so the key has to be generated
        CryptoContextImpl<Element>::s_evalMultKeyMap[key->GetKeyTag()] = {GetScheme()->EvalMultKeyGen(key)};
    }
}

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeysGen(const PrivateKey<Element>& key) {
    ValidateKey(key);
    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(key->GetKeyTag()) ==
        CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // the key is not found in the map, so the key has to be generated
        CryptoContextImpl<Element>::s_evalMultKeyMap[key->GetKeyTag()] = GetScheme()->EvalMultKeysGen(key);
    }
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys() {
    CryptoContextImpl<Element>::s_evalMultKeyMap.clear();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const std::string& keyTag) {
    auto kd = CryptoContextImpl<Element>::s_evalMultKeyMap.find(keyTag);
    if (kd != CryptoContextImpl<Element>::s_evalMultKeyMap.end())
        CryptoContextImpl<Element>::s_evalMultKeyMap.erase(kd);
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const CryptoContext<Element>& cc) {
    for (auto it = CryptoContextImpl<Element>::s_evalMultKeyMap.begin();
         it != CryptoContextImpl<Element>::s_evalMultKeyMap.end();) {
        if (it->second[0]->GetCryptoContext() == cc) {
            it = CryptoContextImpl<Element>::s_evalMultKeyMap.erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(const std::vector<EvalKey<Element>>& vectorToInsert,
                                                   const std::string& keyTag) {
    const std::string& tag = (keyTag.empty()) ? vectorToInsert[0]->GetKeyTag() : keyTag;
    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(tag) != CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // we do not allow to override the existing key vector if its keyTag is identical to the keyTag of the new keys
        OPENFHE_THROW("Can not save a EvalMultKeys vector as there is a key vector for the given keyTag");
    }
    CryptoContextImpl<Element>::s_evalMultKeyMap[tag] = vectorToInsert;
}

/////////////////////////////////////////
// ADVANCED SHE
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(const PrivateKey<Element> privateKey,
                                               const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");
    }

    auto&& evalKeys = GetScheme()->EvalSumKeyGen(privateKey, publicKey);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, uint32_t rowSize, uint32_t subringDim) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag())
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");

    std::vector<uint32_t> indices;
    auto&& evalKeys = GetScheme()->EvalSumRowsKeyGen(privateKey, rowSize, subringDim, indices);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());

    return CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(privateKey->GetKeyTag(), indices);
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag())
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");

    std::vector<uint32_t> indices;
    auto&& evalKeys = GetScheme()->EvalSumColsKeyGen(privateKey, indices);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
    return CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(privateKey->GetKeyTag(), indices);
}

template <typename Element>
const std::map<uint32_t, EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalSumKeyMap(const std::string& keyTag) {
    return CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(keyTag);
}

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>>& CryptoContextImpl<Element>::GetAllEvalMultKeys() {
    return CryptoContextImpl<Element>::s_evalMultKeyMap;
}

template <typename Element>
const std::vector<EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalMultKeyVector(const std::string& keyTag) {
    auto ekv = CryptoContextImpl<Element>::s_evalMultKeyMap.find(keyTag);
    if (ekv == CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        std::string errMsg(std::string("Call EvalMultKeyGen() to have EvalMultKey available for ID [") + keyTag + "].");
        OPENFHE_THROW(errMsg);
    }
    return ekv->second;
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys() {
    return CryptoContextImpl<Element>::s_evalAutomorphismKeyMap;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(
    const std::string& keyTag) {
    auto ekv = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(keyTag);
    if (ekv == CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end()) {
        OPENFHE_THROW("EvalAutomorphismKeys are not generated for ID [" + keyTag + "].");
    }
    return ekv->second;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(
    const std::string& keyTag, const std::vector<uint32_t>& indexList) {
    if (!indexList.size())
        OPENFHE_THROW("indexList is empty");

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> keyMap =
        CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(keyTag);

    // create a return map if specific indices are provided
    std::map<uint32_t, EvalKey<Element>> retMap;
    for (uint32_t indx : indexList) {
        const auto it = keyMap->find(indx);
        if (it == keyMap->end()) {
            OPENFHE_THROW("Key is not generated for index [" + std::to_string(indx) + "] and keyTag [" + keyTag + "]");
        }
        retMap.emplace(indx, it->second);
    }
    return std::make_shared<std::map<uint32_t, EvalKey<Element>>>(retMap);
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalSumKeys() {
    return CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys() {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param keyTag
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const std::string& keyTag) {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(keyTag);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const CryptoContext<Element> cc) {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(cc);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(const PrivateKey<Element> privateKey,
                                                   const std::vector<int32_t>& indexList,
                                                   const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalAtIndexKeyGen does not match private key");
    }

    auto&& evalKeys = GetScheme()->EvalAtIndexKeyGen(publicKey, privateKey, indexList);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys() {
    CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.clear();
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param keyTag
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const std::string& keyTag) {
    auto kd = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(keyTag);
    if (kd != CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end())
        CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const CryptoContext<Element> cc) {
    for (auto it = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.begin();
         it != CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end();) {
        if (it->second->begin()->second->GetCryptoContext() == cc) {
            it = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(const std::string& keyTag) {
    auto keyMapIt = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(keyTag);
    if (keyMapIt == CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end())
        // there is no keys for the given keyTag, return empty vector
        return std::set<uint32_t>();

    // get all inidices from the existing automorphism key map
    auto& keyMap = *(keyMapIt->second);
    std::set<uint32_t> indices;
    for (const auto& [key, _] : keyMap) {
        indices.insert(key);
    }

    return indices;
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::GetUniqueValues(const std::set<uint32_t>& oldValues,
                                                               const std::set<uint32_t>& newValues) {
    std::set<uint32_t> newUniqueValues;
    std::set_difference(newValues.begin(), newValues.end(), oldValues.begin(), oldValues.end(),
                        std::inserter(newUniqueValues, newUniqueValues.begin()));
    return newUniqueValues;
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> mapToInsert, const std::string& keyTag) {
    // check if the map is empty
    if (mapToInsert->empty()) {
        return;
    }

    auto mapToInsertIt    = mapToInsert->begin();
    const std::string& id = (keyTag.empty()) ? mapToInsertIt->second->GetKeyTag() : keyTag;
    std::set<uint32_t> existingIndices{CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(id)};
    if (existingIndices.empty()) {
        // there is no keys for the given id, so we insert full mapToInsert
        CryptoContextImpl<Element>::s_evalAutomorphismKeyMap[id] = mapToInsert;
    }
    else {
        // get all indices from mapToInsert
        std::set<uint32_t> newIndices;
        for (const auto& [key, _] : *mapToInsert) {
            newIndices.insert(key);
        }

        // find all indices in mapToInsert that are not in the exising map and
        // insert those new indices and their corresponding keys to the existing map
        std::set<uint32_t> indicesToInsert{CryptoContextImpl<Element>::GetUniqueValues(existingIndices, newIndices)};
        auto keyMapIt = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(id);
        auto& keyMap  = *(keyMapIt->second);
        for (uint32_t indx : indicesToInsert) {
            keyMap[indx] = (*mapToInsert)[indx];
        }
    }
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(ConstCiphertext<Element>& ciphertext,
                                                        uint32_t batchSize) const {
    ValidateCiphertext(ciphertext);
    auto&& evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    return GetScheme()->EvalSum(ciphertext, batchSize, evalSumKeys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumRows(ConstCiphertext<Element>& ciphertext, uint32_t numRows,
                                                            const std::map<uint32_t, EvalKey<Element>>& evalSumKeys,
                                                            uint32_t subringDim) const {
    ValidateCiphertext(ciphertext);
    return GetScheme()->EvalSumRows(ciphertext, numRows, evalSumKeys, subringDim);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumCols(
    ConstCiphertext<Element>& ciphertext, uint32_t numCols,
    const std::map<uint32_t, EvalKey<Element>>& evalSumKeysRight) const {
    ValidateCiphertext(ciphertext);
    auto&& evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    return GetScheme()->EvalSumCols(ciphertext, numCols, evalSumKeys, evalSumKeysRight);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(ConstCiphertext<Element>& ciphertext, int32_t index) const {
    ValidateCiphertext(ciphertext);
    // If the index is zero, no rotation is needed, copy the ciphertext and return
    // This is done after the keyMap so that it is protected if there's not a valid key.
    if (0 == index)
        return ciphertext->Clone();
    auto&& evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    return GetScheme()->EvalAtIndex(ciphertext, index, evalAutomorphismKeys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalMerge(
    const std::vector<Ciphertext<Element>>& ciphertextVector) const {
    if (0 == ciphertextVector.size())
        OPENFHE_THROW("Input ciphertext vector is empty");
    ValidateCiphertext(ciphertextVector[0]);
    auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertextVector[0]->GetKeyTag());
    return GetScheme()->EvalMerge(ciphertextVector, evalAutomorphismKeys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element>& ct1,
                                                                 ConstCiphertext<Element>& ct2,
                                                                 uint32_t batchSize) const {
    ValidateCiphertext(ct1);
    if (ct2 == nullptr || ct1->GetKeyTag() != ct2->GetKeyTag())
        OPENFHE_THROW("Information was not generated with this crypto context");
    auto& evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());
    auto& ek          = CryptoContextImpl<Element>::GetEvalMultKeyVector(ct1->GetKeyTag());
    return GetScheme()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, ek[0]);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element>& ct1, ConstPlaintext& ct2,
                                                                 uint32_t batchSize) const {
    ValidateCiphertext(ct1);
    if (ct2 == nullptr)
        OPENFHE_THROW("Information was not generated with this crypto context");
    auto& evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());
    return GetScheme()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys);
}

template <typename Element>
Plaintext CryptoContextImpl<Element>::GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                             EncodingParams ep, CKKSDataType cdt) {
    auto vp = std::make_shared<typename NativePoly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
    if (pte == CKKS_PACKED_ENCODING)
        return PlaintextFactory::MakePlaintext(pte, evp, ep, INVALID_SCHEME, cdt);
    return PlaintextFactory::MakePlaintext(pte, vp, ep);
}

template <typename Element>
DecryptResult CryptoContextImpl<Element>::Decrypt(ConstCiphertext<Element>& ciphertext,
                                                  const PrivateKey<Element>& privateKey, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        OPENFHE_THROW("ciphertext is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW("plaintext is empty");
    ValidateKey(privateKey);

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = CryptoContextImpl<Element>::GetPlaintextForDecrypt(
        ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams(),
        this->GetCKKSDataType());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) && (typeid(Element) != typeid(NativePoly))) {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<Poly>());
    }
    else {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<NativePoly>());
    }

    if (result.isValid == false)  // TODO (dsuponit): why don't we throw an exception here?
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
        decryptedCKKS->SetLevel(ciphertext->GetLevel());
        decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
        decryptedCKKS->SetSlots(ciphertext->GetSlots());

        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());

        decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

//------------------------------------------------------------------------------
// Advanced SHE CHEBYSHEV SERIES EXAMPLES
//------------------------------------------------------------------------------

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalChebyshevFunction(std::function<double(double)> func,
                                                                      ConstCiphertext<Element>& ciphertext, double a,
                                                                      double b, uint32_t degree) const {
    std::vector<double> coefficients = EvalChebyshevCoefficients(func, a, b, degree);
    return EvalChebyshevSeries(ciphertext, coefficients, a, b);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSin(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                        uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return std::sin(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalCos(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                        uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return std::cos(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLogistic(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                             uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return 1 / (1 + std::exp(-x)); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalDivide(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                           uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return 1 / x; }, ciphertext, a, b, degree);
}

}  // namespace lbcrypto

// the code below is from cryptocontext-impl.cpp
namespace lbcrypto {

template <>
Plaintext CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                              EncodingParams ep, CKKSDataType cdt) {
    if ((pte == CKKS_PACKED_ENCODING) && (evp->GetParams().size() > 1)) {
        auto vp = std::make_shared<typename Poly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
        return PlaintextFactory::MakePlaintext(pte, vp, ep, INVALID_SCHEME, cdt);
    }
    else {
        auto vp =
            std::make_shared<typename NativePoly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
        return PlaintextFactory::MakePlaintext(pte, vp, ep, INVALID_SCHEME, cdt);
    }
}

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::Decrypt(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const PrivateKey<DCRTPoly>& privateKey, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        OPENFHE_THROW("ciphertext is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW("plaintext is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
        OPENFHE_THROW("Information was not generated with this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
        ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams(),
        this->GetCKKSDataType());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (ciphertext->GetElements()[0].GetParams()->GetParams().size() > 1))  // more than one tower in DCRTPoly
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<Poly>());
    else
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false)
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
        decryptedCKKS->SetLevel(ciphertext->GetLevel());
        decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
        decryptedCKKS->SetSlots(ciphertext->GetSlots());

        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

        decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusion(
    const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec, Plaintext* plaintext) const {
    DecryptResult result;

    // Make sure we're processing ciphertexts.
    size_t last_ciphertext = partialCiphertextVec.size();
    if (last_ciphertext < 1)
        return result;

    for (size_t i = 0; i < last_ciphertext; i++) {
        ValidateCiphertext(partialCiphertextVec[i]);
        if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
            OPENFHE_THROW("Ciphertexts have mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
        partialCiphertextVec[0]->GetEncodingType(), partialCiphertextVec[0]->GetElements()[0].GetParams(),
        this->GetEncodingParams(), this->GetCKKSDataType());

    if ((partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (partialCiphertextVec[0]->GetElements()[0].GetParams()->GetParams().size() > 1))
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<Poly>());
    else
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false)
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetSlots(partialCiphertextVec[0]->GetSlots());
        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
        decryptedCKKS->Decode(partialCiphertextVec[0]->GetNoiseScaleDeg(), partialCiphertextVec[0]->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);

    return result;
}

// static void PrintDCRTPoly(const DCRTPoly& poly, const std::string& name) {
//     DCRTPoly temp = poly;
//     if (temp.GetFormat() == Format::EVALUATION)
//         temp.SwitchFormat();  // NTT domain → coefficient domain

//     std::cout << "==== " << name << " ====" << std::endl;
//     auto towers = temp.GetAllElements();

//     for (size_t i = 0; i < towers.size(); i++) {
//         std::cout << "  Tower " << i 
//                   << " (modulus = " << towers[i].GetModulus() << ")" << std::endl;

//         auto vals = towers[i].GetValues();  
//         size_t len = vals.GetLength();   

//         // Find maximum coefficient in balanced representation [-q/2, q/2)
//         auto modulus = towers[i].GetModulus();
//         uint64_t q = modulus.ConvertToInt<uint64_t>();
//         uint64_t q_half = q / 2;
        
//         int64_t maxAbsCoeff = 0;
//         for (size_t j = 0; j < len; j++) {
//             uint64_t val = vals[j].ConvertToInt<uint64_t>();
//             int64_t balanced;
            
//             if (val > q_half) {
//                 balanced = static_cast<int64_t>(val) - static_cast<int64_t>(q);
//             } else {
//                 balanced = static_cast<int64_t>(val);
//             }
            
//             int64_t absVal = std::abs(balanced);
//             if (absVal > maxAbsCoeff)
//                 maxAbsCoeff = absVal;
//         }
        
//         // Calculate bit length of maximum absolute value
//         int bitLength = 0;
//         if (maxAbsCoeff > 0) {
//             bitLength = 64 - __builtin_clzll(static_cast<uint64_t>(maxAbsCoeff));
//         }
        
//         std::cout << "    Max |coefficient| (balanced): " << maxAbsCoeff 
//                   << " (" << bitLength << " bits)" << std::endl;

//         for (size_t j = 0; j < std::min<size_t>(len, 32); j++)
//             std::cout << vals[j] << " ";
//         if (len > 32)
//             std::cout << "...";
//         std::cout << std::endl;
//     }
//     std::cout << std::endl;
// }

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusionDistributed(
    const Ciphertext<DCRTPoly>& ciphertext,
    const std::unordered_map<uint32_t, Ciphertext<DCRTPoly>>& partials,
    uint32_t threshold,
    Plaintext* plaintext,
    const std::string& shareType,
    bool denomClear,
    uint32_t N) const {

    DecryptResult result;

    if (!ciphertext)
        return result;

    ValidateCiphertext(ciphertext);

    if (partials.size() < threshold)
        return result;

    for (const auto& kv : partials) {
        const auto& ct = kv.second;
        if (!ct)
            return result;
        ValidateCiphertext(ct);
        if (ct->GetEncodingType() != ciphertext->GetEncodingType())
            OPENFHE_THROW("Ciphertexts have mismatched encoding types between original and partials");
    }

    std::vector<uint32_t> client_indexes;
    client_indexes.reserve(partials.size());
    for (const auto& kv : partials)
        client_indexes.push_back(kv.first);
    std::sort(client_indexes.begin(), client_indexes.end());
    client_indexes.erase(std::unique(client_indexes.begin(), client_indexes.end()), client_indexes.end());

    const size_t L = client_indexes.size();
    if (L < threshold)
        return result;

    const auto& elemsOrig = ciphertext->GetElements();
    if (elemsOrig.size() < 2)
        OPENFHE_THROW("Original ciphertext must have two elements (c0, c1)");

    auto  elementParams = elemsOrig[0].GetParams();
    size_t vecSize      = elementParams->GetParams().size();
    usint Ndim          = elementParams->GetRingDimension();

    DCRTPoly c0 = elemsOrig[0];
    c0.SetFormat(Format::EVALUATION);

    // =========================
    // additive: c0 + Σ(partial)
    // =========================
    if (shareType == "additive") {
        DCRTPoly fusedSum(elementParams, Format::EVALUATION, true);

        for (size_t j = 0; j < L; ++j) {
            const uint32_t pid = client_indexes[j];
            auto it = partials.find(pid);
            if (it == partials.end())
                OPENFHE_THROW("Missing partial share for a listed client index");

            const auto& ctj   = it->second;
            const auto& elems = ctj->GetElements();
            if (elems.size() < 1)
                OPENFHE_THROW("Partial ciphertext must have a single element (s_i*c1 + noise)");

            DCRTPoly sharePoly = elems[0];
            sharePoly.SetFormat(Format::EVALUATION);
            fusedSum += sharePoly;
        }

        fusedSum += c0;

        auto fusedCt = ciphertext->CloneEmpty();
        fusedCt->SetElement(std::move(fusedSum));

        Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
            fusedCt->GetEncodingType(), fusedCt->GetElements()[0].GetParams(),
            this->GetEncodingParams(), this->GetCKKSDataType());

        if ((fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) &&
            (fusedCt->GetElements()[0].GetParams()->GetParams().size() > 1))
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                          &decrypted->GetElement<Poly>());
        else
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                          &decrypted->GetElement<NativePoly>());

        if (!result.isValid)
            return result;

        decrypted->SetScalingFactorInt(result.scalingFactorInt);

        if (fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) {
            auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetSlots(ciphertext->GetSlots());
            const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
            decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                                  cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
        } else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);
        return result;
    }

    // ===========================================
    // shamir: c0 + Σ( L_j(0) · partial_j )  (both uncleared and cleared)
    // ===========================================
    else if (shareType == "shamir") {
        std::vector<DCRTPoly> Lconsts;
        Lconsts.reserve(L);

        for (size_t j = 0; j < L; ++j) {
            const auto cj = client_indexes[j];
            DCRTPoly LjConst(elementParams, Format::COEFFICIENT, true);

            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();

                NativeInteger Nfact(1);                
                if (denomClear) {
                    for (usint t = 2; t <= N; ++t)
                        Nfact = Nfact.ModMul(NativeInteger(t), modq_k);
                }
                Nfact = Nfact.ModMul(Nfact, modq_k);

                NativeInteger numerator(1);
                NativeInteger denominator(1);

                for (size_t i = 0; i < L; ++i) {
                    if (i == j) continue;
                    auto ci = client_indexes[i];

                    // denominator (ci - cj) mod q_k
                    NativeInteger denom = (ci >= cj) ? NativeInteger(ci - cj)
                                                     : (modq_k - NativeInteger(cj - ci));

                    numerator   = numerator.ModMul(NativeInteger(ci), modq_k);
                    denominator = denominator.ModMul(denom, modq_k);
                }

                auto denomInv  = denominator.ModInverse(modq_k);
                auto Lj_val    = numerator.ModMul(denomInv, modq_k);
                auto Lj_scaled = denomClear ? Lj_val.ModMul(Nfact, modq_k) : Lj_val;

                NativePoly poly(params_k, Format::COEFFICIENT, true);
                poly[0] = Lj_scaled;
                LjConst.SetElementAtIndex(k, std::move(poly));
            }

            LjConst.SetFormat(Format::EVALUATION);
            Lconsts.emplace_back(std::move(LjConst));
        }

        DCRTPoly fusedSum(elementParams, Format::EVALUATION, true);

        for (size_t j = 0; j < L; ++j) {
            const uint32_t pid = client_indexes[j];
            auto it = partials.find(pid);
            if (it == partials.end())
                OPENFHE_THROW("Missing partial share for a listed client index");

            const auto& ctj   = it->second;
            const auto& elems = ctj->GetElements();
            if (elems.size() < 1)
                OPENFHE_THROW("Partial ciphertext must have a single element");

            DCRTPoly sharePoly = elems[0];
            sharePoly.SetFormat(Format::EVALUATION);

            fusedSum += Lconsts[j] * sharePoly;
        }

        if (denomClear) {
            DCRTPoly NfactConst(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();
                NativeInteger Nfact_k(1);
                for (usint t = 2; t <= N; ++t)
                    Nfact_k = Nfact_k.ModMul(NativeInteger(t), modq_k);
                Nfact_k = Nfact_k.ModMul(Nfact_k, modq_k);

                NativePoly poly(params_k, Format::COEFFICIENT, true);
                poly[0] = Nfact_k;
                NfactConst.SetElementAtIndex(k, std::move(poly));
            }
            NfactConst.SetFormat(Format::EVALUATION);
            fusedSum += c0 * NfactConst;
        } else {
            fusedSum += c0;
        }

        auto fusedCt = ciphertext->CloneEmpty();
        fusedCt->SetElement(std::move(fusedSum));

        Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
            fusedCt->GetEncodingType(), fusedCt->GetElements()[0].GetParams(),
            this->GetEncodingParams(), this->GetCKKSDataType());

        DecryptResult localRes;

        if ((fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) &&
            (fusedCt->GetElements()[0].GetParams()->GetParams().size() > 1))
            localRes = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                            &decrypted->GetElement<Poly>());
        else
            localRes = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                            &decrypted->GetElement<NativePoly>());

        if (!localRes.isValid)
            OPENFHE_THROW("Fusion decrypt failed");

        decrypted->SetScalingFactorInt(localRes.scalingFactorInt);

        if (fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) {
            auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetSlots(ciphertext->GetSlots());
            const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
            decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                                  cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
        } else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);
        return result;
    }
    // -------------------------
    // 2adic  (distributed fusion at x = -1)
    // -------------------------
    else if (shareType == "2adic") {
        const uint64_t Lexp = static_cast<uint64_t>(threshold - 1);
        const uint64_t two_n = 2ULL * static_cast<uint64_t>(Ndim);

        uint64_t M = 1;
        while (M < static_cast<uint64_t>(N)) M <<= 1;
        const uint64_t h = two_n / M;

        // α_j = X^{h * cid_j}
        std::vector<DCRTPoly> alphas;
        alphas.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            const uint64_t cid = static_cast<uint64_t>(client_indexes[j]);
            const unsigned __int128 sigma = static_cast<unsigned __int128>(h) * cid;

            const uint64_t r    = static_cast<uint64_t>(sigma % Ndim);
            const bool negWrap  = (static_cast<unsigned __int128>(sigma / Ndim) & 1) != 0;

            DCRTPoly alpha(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = elementParams->GetParams()[k];
                auto modq_k = pk->GetModulus();
                NativePoly mono(pk, Format::COEFFICIENT, true);
                mono[r] = negWrap ? (modq_k - 1) : NativeInteger(1); // ±X^r
                alpha.SetElementAtIndex(k, std::move(mono));
            }
            alphas.emplace_back(std::move(alpha));
        }

        std::vector<DCRTPoly> Ljs;
        Ljs.reserve(L);

        // L_j(-1) = ∏_{i≠j} ( -1 - α_i ) * (α_j - α_i)^{-1}
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly NumeratorEval(elementParams, Format::COEFFICIENT, true);
            DCRTPoly DenominatorEval(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk = elementParams->GetParams()[k];
                NativePoly one(pk, Format::COEFFICIENT, true);
                one[0] = NativeInteger(1);
                NumeratorEval.SetElementAtIndex(k, one);
                DenominatorEval.SetElementAtIndex(k, one);
            }

            // (-1) in COEFFICIENT
            DCRTPoly minusOneCoeff(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = elementParams->GetParams()[k];
                auto modq_k = pk->GetModulus();
                NativePoly c(pk, Format::COEFFICIENT, true);
                c[0] = modq_k - NativeInteger(1); // -1 mod q
                minusOneCoeff.SetElementAtIndex(k, std::move(c));
            }

            for (size_t i = 0; i < L; ++i) {
                if (i == j) continue;

                // Build in COEFFICIENT
                DCRTPoly x0MinusAlphaI = minusOneCoeff - alphas[i];   // (-1 - α_i)
                DCRTPoly denom         = alphas[j].Minus(alphas[i]);  // (α_j - α_i)

                // Move to EVALUATION
                x0MinusAlphaI.SetFormat(Format::EVALUATION);
                denom.SetFormat(Format::EVALUATION);
                NumeratorEval.SetFormat(Format::EVALUATION);
                DenominatorEval.SetFormat(Format::EVALUATION);

                NumeratorEval   *= x0MinusAlphaI;
                DenominatorEval *= denom;
            }

            // Component-wise inverse of denominator
            DCRTPoly DenInvEval(elementParams, Format::EVALUATION, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto& den_k  = DenominatorEval.GetElementAtIndex(k);
                auto  vals   = den_k.GetValues();
                auto  pk     = elementParams->GetParams()[k];
                auto  modq_k = pk->GetModulus();
                usint len    = vals.GetLength();

                NativeVector invVals(len, modq_k);
                for (usint s = 0; s < len; ++s)
                    invVals[s] = vals[s].ModInverse(modq_k);

                NativePoly invPoly(pk, Format::EVALUATION, true);
                invPoly.SetValues(std::move(invVals), Format::EVALUATION);
                DenInvEval.SetElementAtIndex(k, std::move(invPoly));
            }

            DCRTPoly Lj = NumeratorEval * DenInvEval;

            if (denomClear) {
                // Optional clearing factor Δ = 2^{t-1} per tower
                DCRTPoly Delta(elementParams, Format::COEFFICIENT, true);
                for (size_t k = 0; k < vecSize; ++k) {
                    auto params_k = elementParams->GetParams()[k];
                    auto modq_k   = params_k->GetModulus();
                    NativeInteger pow2L = NativeInteger(2).ModExp(NativeInteger(Lexp), modq_k);
                    NativePoly poly(params_k, Format::COEFFICIENT, true);
                    poly[0] = pow2L;
                    Delta.SetElementAtIndex(k, std::move(poly));
                }
                Delta.SetFormat(Format::EVALUATION);
                Lj *= Delta;
            }

            Ljs.emplace_back(std::move(Lj));
        }

        // fusedSum = c0(+Δ) + Σ_j L_j(-1)(·Δ) * partial_j
        DCRTPoly fusedSum(elementParams, Format::EVALUATION, true);
        for (size_t j = 0; j < L; ++j) {
            const uint32_t pid = client_indexes[j];
            auto it = partials.find(pid);
            if (it == partials.end())
                OPENFHE_THROW("Missing partial share for a listed client index");
            const auto& ctj   = it->second;
            const auto& elems = ctj->GetElements();
            if (elems.size() < 1)
                OPENFHE_THROW("Partial ciphertext must have a single element");
            DCRTPoly sharePoly = elems[0];
            sharePoly.SetFormat(Format::EVALUATION);
            fusedSum += Ljs[j] * sharePoly;
        }

        if (denomClear) {
            DCRTPoly TwoLConst(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();
                NativeInteger pow2L = NativeInteger(2).ModExp(NativeInteger(Lexp), modq_k);
                NativePoly poly(params_k, Format::COEFFICIENT, true);
                poly[0] = pow2L;
                TwoLConst.SetElementAtIndex(k, std::move(poly));
            }
            TwoLConst.SetFormat(Format::EVALUATION);
            fusedSum += c0 * TwoLConst;
        } else {
            fusedSum += c0;
        }

        auto fusedCt = ciphertext->CloneEmpty();
        fusedCt->SetElement(std::move(fusedSum));

        Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
            fusedCt->GetEncodingType(),
            fusedCt->GetElements()[0].GetParams(),
            this->GetEncodingParams(),
            this->GetCKKSDataType());

        if ((fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) &&
            (fusedCt->GetElements()[0].GetParams()->GetParams().size() > 1))
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                        &decrypted->GetElement<Poly>());
        else
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                        &decrypted->GetElement<NativePoly>());

        if (!result.isValid)
            return result;

        decrypted->SetScalingFactorInt(result.scalingFactorInt);

        if (fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) {
            auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetSlots(ciphertext->GetSlots());
            const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
            decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                                cryptoParamsCKKS->GetScalingTechnique(),
                                cryptoParamsCKKS->GetExecutionMode());
        } else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);
        return result;
    }

    // ===========================================
    // BFM+25: c0(+Δ) + Σ( L_j(0)(·Δ) · partial_j )
    // ===========================================
    else if (shareType == "BFM+25") {
        std::vector<DCRTPoly> alphas;
        alphas.reserve(L);
        for (size_t u = 0; u < L; ++u) {
            const uint32_t pid  = client_indexes[u];
            const uint32_t idx  = pid - 1;
            const uint32_t iBit = (idx & 1u);
            const uint64_t jExp = static_cast<uint64_t>(idx >> 1);

            DCRTPoly alpha(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = elementParams->GetParams()[k];
                auto modq_k = pk->GetModulus();
                NativePoly mono(pk, Format::COEFFICIENT, true);
                const usint pos = static_cast<usint>(jExp % Ndim);
                mono[pos] = (iBit ? (modq_k - 1) : NativeInteger(1));
                alpha.SetElementAtIndex(k, std::move(mono));
            }
            alphas.emplace_back(std::move(alpha));
        }

        std::vector<DCRTPoly> Ljs;
        Ljs.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly NumeratorEval(elementParams, Format::COEFFICIENT, true);
            DCRTPoly DenominatorEval(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk = elementParams->GetParams()[k];
                NativePoly one(pk, Format::COEFFICIENT, true);
                one[0] = NativeInteger(1);
                NumeratorEval.SetElementAtIndex(k, one);
                DenominatorEval.SetElementAtIndex(k, one);
            }
            NumeratorEval.SetFormat(Format::EVALUATION);
            DenominatorEval.SetFormat(Format::EVALUATION);

            for (size_t i = 0; i < L; ++i) {
                if (i == j) continue;
                DCRTPoly negAlphaI = alphas[i].Negate();
                DCRTPoly denom     = alphas[j].Minus(alphas[i]);
                negAlphaI.SetFormat(Format::EVALUATION);
                denom.SetFormat(Format::EVALUATION);
                NumeratorEval   *= negAlphaI;
                DenominatorEval *= denom;
            }

            DCRTPoly DenInvEval(elementParams, Format::EVALUATION, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto       pk     = elementParams->GetParams()[k];
                auto       modq_k = pk->GetModulus();
                const auto& den_k = DenominatorEval.GetElementAtIndex(k);
                auto       vals   = den_k.GetValues();
                usint      len    = vals.GetLength();
                NativeVector invVals(len, modq_k);
                for (usint s = 0; s < len; ++s) {
                    invVals[s] = vals[s].ModInverse(modq_k);
                }
                NativePoly invPoly(pk, Format::EVALUATION, true);
                invPoly.SetValues(std::move(invVals), Format::EVALUATION);
                DenInvEval.SetElementAtIndex(k, std::move(invPoly));
            }
            // PrintDCRTPoly(NumeratorEval, "NumeratorEval");
            // PrintDCRTPoly(DenominatorEval, "DenominatorEval");
            // PrintDCRTPoly(DenInvEval, "DenInvEval");    

            DCRTPoly Lj = NumeratorEval * DenInvEval;
            Ljs.emplace_back(std::move(Lj));
        }

        DCRTPoly DeltaEval(elementParams, Format::EVALUATION, true);
        if (denomClear) {
            const size_t vecSizeDelta = elementParams->GetParams().size();
            const usint  NdimDelta    = elementParams->GetRingDimension();
            DCRTPoly Delta(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSizeDelta; ++k) {
                auto pk     = elementParams->GetParams()[k];
                auto modq_k = pk->GetModulus();
                NativePoly two(pk, Format::COEFFICIENT, true);
                two[0] = NativeInteger(2) % modq_k;
                Delta.SetElementAtIndex(k, std::move(two));
            }
            Delta.SetFormat(Format::EVALUATION);
            auto mul_term = [&](usint deg) {
                DCRTPoly term(elementParams, Format::COEFFICIENT, true);
                for (size_t k = 0; k < vecSizeDelta; ++k) {
                    auto pk     = elementParams->GetParams()[k];
                    auto modq_k = pk->GetModulus();
                    NativePoly poly(pk, Format::COEFFICIENT, true);
                    poly[deg % NdimDelta] = NativeInteger(1);
                    poly[0] = modq_k - NativeInteger(1);
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
            DeltaEval = std::move(Delta);
            for (auto& Lj : Ljs)
                Lj *= DeltaEval;
        }

        DCRTPoly fusedSum(elementParams, Format::EVALUATION, true);
        for (size_t j = 0; j < L; ++j) {
            const uint32_t pid = client_indexes[j];
            auto it = partials.find(pid);
            if (it == partials.end())
                OPENFHE_THROW("Missing partial share for a listed client index");
            const auto& ctj   = it->second;
            const auto& elems = ctj->GetElements();
            if (elems.size() < 1)
                OPENFHE_THROW("Partial ciphertext must have a single element (s_i*c1 + noise)");
            DCRTPoly sharePoly = elems[0];
            sharePoly.SetFormat(Format::EVALUATION);
            fusedSum += (Ljs[j] * sharePoly);
        }

        if (denomClear)
            fusedSum += (c0 * DeltaEval);
        else
            fusedSum += c0;

        auto fusedCt = ciphertext->CloneEmpty();
        fusedCt->SetElement(std::move(fusedSum));

        Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
            fusedCt->GetEncodingType(),
            fusedCt->GetElements()[0].GetParams(),
            this->GetEncodingParams(),
            this->GetCKKSDataType());

        if ((fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) &&
            (fusedCt->GetElements()[0].GetParams()->GetParams().size() > 1))
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                        &decrypted->GetElement<Poly>());
        else
            result = GetScheme()->MultipartyDecryptFusion(std::vector<Ciphertext<DCRTPoly>>{fusedCt},
                                                        &decrypted->GetElement<NativePoly>());

        if (!result.isValid)
            return result;

        decrypted->SetScalingFactorInt(result.scalingFactorInt);

        if (fusedCt->GetEncodingType() == CKKS_PACKED_ENCODING) {
            auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetSlots(ciphertext->GetSlots());
            const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
            decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                                cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
        } else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);
        return result;
    }
    else {
        OPENFHE_THROW("Unknown shareType in fusion");
    }
}



template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootAdjustScale(ConstCiphertext<Element>& ciphertext) const {
    return GetScheme()->IntMPBootAdjustScale(ciphertext);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootRandomElementGen(const PublicKey<Element> publicKey) const {
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
    return GetScheme()->IntMPBootRandomElementGen(cryptoParamsCKKS, publicKey);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                                              ConstCiphertext<Element>& ciphertext,
                                                                              ConstCiphertext<Element>& a) const {
    return GetScheme()->IntMPBootDecrypt(privateKey, ciphertext, a);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::IntMPBootAdd(
    std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const {
    return GetScheme()->IntMPBootAdd(sharesPairVec);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                                                 const std::vector<Ciphertext<Element>>& sharesPair,
                                                                 ConstCiphertext<Element>& a,
                                                                 ConstCiphertext<Element>& ciphertext) const {
    return GetScheme()->IntMPBootEncrypt(publicKey, sharesPair, a, ciphertext);
}

// Function for sharing and recovery of secret for Threshold FHE with aborts
template <>
std::unordered_map<uint32_t, DCRTPoly> CryptoContextImpl<DCRTPoly>::ShareKeys(const PrivateKey<DCRTPoly>& sk,
                                                                              uint32_t N, uint32_t threshold,
                                                                              uint32_t index,
                                                                              const std::string& shareType) const {
    // conditions on N and threshold for security with aborts
    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 3 for aborts");

    // temporary disabled to allow small T
    // if (threshold <= N / 2)
    //     OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto cryptoParams = sk->GetCryptoContext()->GetCryptoParameters();
    auto elementParams      = cryptoParams->GetElementParams();
    auto vecSize            = elementParams->GetParams().size();
    auto ring_dimension     = elementParams->GetRingDimension();

    // condition for inverse in lagrange coeff to exist.
    for (size_t i = 0; i < vecSize; ++i) {
        auto modq_k = elementParams->GetParams()[i]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N needs to be less than DCRTPoly moduli");
    }

    // secret sharing
    std::unordered_map<uint32_t, DCRTPoly> SecretShares;

    if (shareType == "additive") {
        // generate a random share of N-2 elements and create the last share as sk - (sk_1 + ... + sk_N-2)
        typename DCRTPoly::DugType dug;
        DCRTPoly rsum(dug, elementParams, Format::EVALUATION);

        const uint32_t num_of_shares = N - 1;
        std::vector<DCRTPoly> SecretSharesVec;
        SecretSharesVec.reserve(num_of_shares);
        SecretSharesVec.push_back(rsum);
        for (size_t i = 1; i < num_of_shares - 1; ++i) {
            DCRTPoly r(dug, elementParams, Format::EVALUATION);  // should re-generate uniform r for each share
            rsum += r;
            SecretSharesVec.push_back(std::move(r));
        }
        SecretSharesVec.push_back(sk->GetPrivateElement() - rsum);

        for (size_t i = 1, ctr = 0; i <= N; ++i) {
            if (i != index) {
                SecretShares[i] = SecretSharesVec[ctr++];
            }
        }
    }
    else if (shareType == "shamir") {
        // vector to store columnwise randomly generated coefficients for polynomial f from Z_q for every secret key entry
        // set constant term of polynomial f_i to s_i
        std::vector<DCRTPoly> fs{sk->GetPrivateElement()};
        fs.back().SetFormat(Format::COEFFICIENT);

        // generate random coefficients
        fs.reserve(threshold);
        typename DCRTPoly::DugType dug;
        for (size_t i = 1; i < threshold; ++i) {
            fs.emplace_back(dug, elementParams, Format::COEFFICIENT);
        }

        // evaluate the polynomial at the index of the parties 1 to N
        for (size_t i = 1; i <= N; ++i) {
            if (i != index) {
                DCRTPoly feval(elementParams, Format::COEFFICIENT, true);
                for (size_t k = 0; k < vecSize; k++) {
                    auto modq_k = elementParams->GetParams()[k]->GetModulus();

                    NativePoly powtemppoly(elementParams->GetParams()[k], Format::COEFFICIENT);
                    NativePoly fevalpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);

                    NativeInteger powtemp(1);
                    for (size_t t = 1; t < threshold; t++) {
                        NativeVector powtempvec(ring_dimension, modq_k, (powtemp = powtemp.ModMul(i, modq_k)));

                        powtemppoly.SetValues(std::move(powtempvec), Format::COEFFICIENT);

                        auto& fst = fs[t].GetElementAtIndex(k);

                        for (size_t i = 0; i < ring_dimension; ++i) {
                            fevalpoly[i] += powtemppoly[i].ModMul(fst[i], modq_k);
                        }
                    }
                    fevalpoly += fs[0].GetElementAtIndex(k);

                    fevalpoly.SetFormat(Format::COEFFICIENT);
                    feval.SetElementAtIndex(k, std::move(fevalpoly));
                }
                // assign fi
                SecretShares.emplace(i, std::move(feval));
            }
        }
    }
    else if (shareType == "2adic") {
        // f(x) = fs[0] + fs[1] x + ... + fs[threshold-1] x^{threshold-1}
        std::vector<DCRTPoly> fs{sk->GetPrivateElement()};
        fs.back().SetFormat(Format::COEFFICIENT);

        // generate random coefficients
        fs.reserve(threshold);
        typename DCRTPoly::DugType dug;
        for (size_t t = 1; t < threshold; ++t) {
            fs.emplace_back(dug, elementParams, Format::COEFFICIENT);
        }

        const usint Ndim = elementParams->GetRingDimension(); // cyclotomic degree (usually N)

        // evaluate at ring points { x^1, x^2, ..., x^N }:
        // each party pid gets f(x^{pid})
        for (size_t pid = 1; pid <= N; ++pid) {
            if (pid == index)
                continue;

            DCRTPoly feval(elementParams, Format::COEFFICIENT, /*initializeZero=*/true);

            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();

                // fevalpoly <- fs[0]  (constant term)
                NativePoly fevalpoly(params_k, Format::COEFFICIENT, /*initZero=*/true);
                fevalpoly += fs[0].GetElementAtIndex(k); // both in COEFF

                // For t = 1..threshold-1, add fs[t] * (x^{pid})^t = fs[t] * x^{pid*t}
                for (size_t t = 1; t < threshold; ++t) {
                    // exponent e = pid * t
                    const uint64_t e  = static_cast<uint64_t>(pid) * static_cast<uint64_t>(t);
                    const uint64_t r  = e % Ndim;                  // position of monomial
                    const uint64_t qv = e / Ndim;                  // how many wraps by N
                    const bool neg    = (qv & 1ULL) != 0ULL;       // (-1)^{qv}
                    const NativeInteger coef = neg ? (modq_k - 1)  // -1 mod q_k
                                                : NativeInteger(1);

                    // build monomial powpoly = coef * x^{r}  in R_{q_k}
                    NativePoly powpoly(params_k, Format::COEFFICIENT, /*initZero=*/true);
                    powpoly[r] = coef;

                    // fevalpoly += fs[t]_k * powpoly   (ring conv in COEFF domain)
                    // NOTE: fs[t].GetElementAtIndex(k) and powpoly are both NativePoly in COEFF
                    fevalpoly += fs[t].GetElementAtIndex(k) * powpoly;
                }

                fevalpoly.SetFormat(Format::COEFFICIENT);
                feval.SetElementAtIndex(k, std::move(fevalpoly));
            }

            // assign f(x^{pid})
            SecretShares.emplace(pid, std::move(feval));
        }
    }

    return SecretShares;
}

template <>
void CryptoContextImpl<DCRTPoly>::RecoverSharedKey(PrivateKey<DCRTPoly>& sk,
                                                   std::unordered_map<uint32_t, DCRTPoly>& sk_shares, uint32_t N,
                                                   uint32_t threshold, const std::string& shareType) const {
    if (sk_shares.size() < threshold)
        OPENFHE_THROW("Number of shares available less than threshold of the sharing scheme");

    // conditions on N and threshold for security with aborts
    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 3 for aborts");

    // temporary disabled to allow small T
    // if (threshold <= N / 2)
    //     OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto& cryptoParams  = sk->GetCryptoContext()->GetCryptoParameters();
    const auto& elementParams = cryptoParams->GetElementParams();
    size_t ring_dimension     = elementParams->GetRingDimension();
    size_t vecSize            = elementParams->GetParams().size();

    // condition for inverse in lagrange coeff to exist.
    for (size_t k = 0; k < vecSize; k++) {
        auto modq_k = elementParams->GetParams()[k]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N needs to be less than DCRTPoly moduli");
    }

    // vector of indexes of the clients
    std::vector<uint32_t> client_indexes;
    client_indexes.reserve(N);
    for (uint32_t i = 1; i <= N; ++i) {
        if (sk_shares.find(i) != sk_shares.end())
            client_indexes.push_back(i);
    }
    const uint32_t client_indexes_size = client_indexes.size();

    if (client_indexes_size < threshold)
        OPENFHE_THROW("Not enough shares to recover the secret");

    if (shareType == "additive") {
        DCRTPoly sum_of_elems(elementParams, Format::EVALUATION, true);
        for (uint32_t i = 0; i < threshold; ++i) {
            sum_of_elems += sk_shares[client_indexes[i]];
        }
        sk->SetPrivateElement(std::move(sum_of_elems));
    }
    else if (shareType == "shamir") {
        // use lagrange interpolation to recover the secret
        // vector of lagrange coefficients L_j = Pdt_i ne j (i (i-j)^-1)
        std::vector<DCRTPoly> Lagrange_coeffs(client_indexes_size, DCRTPoly(elementParams, Format::EVALUATION));

        // recovery of the secret with lagrange coefficients and the secret shares
        for (uint32_t j = 0; j < client_indexes_size; j++) {
            auto cj = client_indexes[j];
            for (size_t k = 0; k < vecSize; k++) {
                auto modq_k = elementParams->GetParams()[k]->GetModulus();
                NativePoly multpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
                multpoly.AddILElementOne();
                for (uint32_t i = 0; i < client_indexes_size; i++) {
                    auto ci = client_indexes[i];
                    if (ci != cj) {
                        auto&& denominator = (cj < ci) ? NativeInteger(ci - cj) : modq_k - NativeInteger(cj - ci);
                        auto denom_inv{denominator.ModInverse(modq_k)};
                        for (size_t d = 0; d < ring_dimension; ++d)
                            multpoly[d].ModMulFastEq(NativeInteger(ci).ModMul(denom_inv, modq_k), modq_k);
                    }
                }
                multpoly.SetFormat(Format::EVALUATION);
                Lagrange_coeffs[j].SetElementAtIndex(k, std::move(multpoly));
            }
            Lagrange_coeffs[j].SetFormat(Format::COEFFICIENT);
        }

        DCRTPoly lagrange_sum_of_elems(elementParams, Format::COEFFICIENT, true);
        for (size_t k = 0; k < vecSize; ++k) {
            NativePoly lagrange_sum_of_elems_poly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
            for (uint32_t i = 0; i < client_indexes_size; ++i) {
                const auto& coeff = Lagrange_coeffs[i].GetAllElements()[k];
                const auto& share = sk_shares[client_indexes[i]].GetAllElements()[k];
                lagrange_sum_of_elems_poly += coeff.TimesNoCheck(share);
            }
            lagrange_sum_of_elems.SetElementAtIndex(k, std::move(lagrange_sum_of_elems_poly));
        }
        lagrange_sum_of_elems.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(std::move(lagrange_sum_of_elems));
    }
    else if (shareType == "2adic") {
        // 2-adic: evaluation points are ring elements alpha_j = x^{client_index_j}
        // We reconstruct s = f(0) = sum_j f(alpha_j) * L_j,
        // where L_j = prod_{i!=j} (-alpha_i) * (alpha_j - alpha_i)^{-1}  in R_q.
        // NOTE: (alpha_j - alpha_i) must be invertible in R_q; otherwise, throw.

        const auto& params = elementParams;
        const usint Ndim   = params->GetRingDimension();
        const size_t L     = client_indexes_size; // number of shares used (>= threshold)

        // Precompute alpha_j = x^{c_j} in COEFFICIENT format as DCRTPoly
        std::vector<DCRTPoly> alphas;
        alphas.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            const uint32_t cj = client_indexes[j];

            // Build alpha_j as a DCRTPoly monomial: alpha_j = (-1)^{floor(cj/N)} * x^{(cj mod N)}
            const uint64_t e  = static_cast<uint64_t>(cj);
            const uint64_t r  = e % Ndim;
            const uint64_t qv = e / Ndim;
            const bool negWrap = (qv & 1ULL) != 0ULL;

            DCRTPoly alpha(params, Format::COEFFICIENT, /*initZero=*/true);
            // Set monomial per tower
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = params->GetParams()[k];
                auto modq_k = pk->GetModulus();

                NativePoly mono(pk, Format::COEFFICIENT, /*initZero=*/true);
                mono[r] = negWrap ? (modq_k - 1) : NativeInteger(1);
                alpha.SetElementAtIndex(k, std::move(mono));
            }
            alphas.emplace_back(std::move(alpha));
        }

        // Build Lagrange coefficients L_j in R_q
        std::vector<DCRTPoly> Ljs;
        Ljs.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            // L_j = Π_{i!=j} [ (-alpha_i) * (alpha_j - alpha_i)^{-1} ]
            DCRTPoly Lj(params, Format::COEFFICIENT, /*initZero=*/true);
            Lj.AddILElementOne(); // multiplicative identity "1" in R_q

            for (size_t i = 0; i < L; ++i) {
                if (i == j) continue;

                // (-alpha_i)
                DCRTPoly negAlphaI = alphas[i].Negate();

                // denom = (alpha_j - alpha_i)
                DCRTPoly denom = alphas[j].Minus(alphas[i]);

                // Check invertibility
                if (!denom.InverseExists()) {
                    OPENFHE_THROW("2-adic recovery failed: (alpha_j - alpha_i) is not invertible in R_q");
                }
                DCRTPoly denomInv = denom.MultiplicativeInverse();

                // multiply the factor into Lj
                Lj *= negAlphaI;
                Lj *= denomInv;
            }

            Ljs.emplace_back(std::move(Lj));
        }

        // Reconstruct s = sum_j L_j * share_j  in R_q (COEFFICIENT)
        DCRTPoly s_rec(params, Format::COEFFICIENT, /*initZero=*/true);
        for (size_t j = 0; j < L; ++j) {
            const uint32_t cj = client_indexes[j];
            // Ensure both are in COEFFICIENT (shares are produced in COEFFICIENT above)
            DCRTPoly term = Ljs[j] * sk_shares[cj];
            s_rec += term;
        }

        // Switch to EVALUATION to match the rest of the pipeline (like shamir branch does at the end)
        s_rec.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(std::move(s_rec));
    }

}

// ============================================================================
// Dealer-based secret sharing (additive, shamir, 2adic)
// Dealer generates all N shares and can recover the secret from them.
// ============================================================================
template <>
std::unordered_map<uint32_t, DCRTPoly> CryptoContextImpl<DCRTPoly>::ShareKeysDealer(
    const PrivateKey<DCRTPoly>& sk,
    uint32_t N, uint32_t threshold,
    const std::string& shareType) const {

    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 2 for sharing");

    // temporary disabled to allow small T
    // if (threshold <= N / 2)
    //     OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto cryptoParams = sk->GetCryptoContext()->GetCryptoParameters();
    auto elementParams      = cryptoParams->GetElementParams();
    auto vecSize            = elementParams->GetParams().size();
    auto ring_dimension     = elementParams->GetRingDimension();

    // simple modulus sanity check (same as original)
    for (size_t i = 0; i < vecSize; ++i) {
        auto modq_k = elementParams->GetParams()[i]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N must be less than modulus q");
    }

    std::unordered_map<uint32_t, DCRTPoly> SecretShares;

    // -------------------------
    // additive (N-of-N)
    // -------------------------
    if (shareType == "additive") {
        typename DCRTPoly::DugType dug;
        DCRTPoly rsum(dug, elementParams, Format::EVALUATION);

        // create N shares total: N-1 random + 1 = sk - sum(randoms)
        const uint32_t num_of_shares = N;
        std::vector<DCRTPoly> SecretSharesVec;
        SecretSharesVec.reserve(num_of_shares);

        for (size_t i = 0; i < num_of_shares - 1; ++i) {
            DCRTPoly r(dug, elementParams, Format::EVALUATION);
            rsum += r;
            SecretSharesVec.push_back(std::move(r));
        }
        SecretSharesVec.push_back(sk->GetPrivateElement() - rsum);

        for (size_t i = 1, ctr = 0; i <= N; ++i)
            SecretShares[i] = SecretSharesVec[ctr++];
    }

    // -------------------------
    // shamir
    // -------------------------
    else if (shareType == "shamir") {
        std::vector<DCRTPoly> fs{sk->GetPrivateElement()};
        fs.back().SetFormat(Format::COEFFICIENT);

        fs.reserve(threshold);
        typename DCRTPoly::DugType dug;
        for (size_t i = 1; i < threshold; ++i)
            fs.emplace_back(dug, elementParams, Format::COEFFICIENT);

        for (size_t i = 1; i <= N; ++i) {
            DCRTPoly feval(elementParams, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; k++) {
                auto modq_k = elementParams->GetParams()[k]->GetModulus();

                NativePoly powtemppoly(elementParams->GetParams()[k], Format::COEFFICIENT);
                NativePoly fevalpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);

                NativeInteger powtemp(1);
                for (size_t t = 1; t < threshold; t++) {
                    NativeVector powtempvec(ring_dimension, modq_k, (powtemp = powtemp.ModMul(i, modq_k)));
                    powtemppoly.SetValues(std::move(powtempvec), Format::COEFFICIENT);

                    auto& fst = fs[t].GetElementAtIndex(k);
                    for (size_t j = 0; j < ring_dimension; ++j)
                        fevalpoly[j] += powtemppoly[j].ModMul(fst[j], modq_k);
                }

                fevalpoly += fs[0].GetElementAtIndex(k);
                feval.SetElementAtIndex(k, std::move(fevalpoly));
            }
            SecretShares.emplace(i, std::move(feval));
        }
    }

    // -------------------------
    // BFM+25 (public points: {1, -1, x, -x, x^2, -x^2, ...})
    // f is evaluated at α_{(i,j)} = (-1)^i * X^j over R_Q (negacyclic: X^n = -1).
    // -------------------------
    else if (shareType == "BFM+25") {
        // f(x) = f0 + f1 x + ... + f_{t-1} x^{t-1}, with f0 = sk
        std::vector<DCRTPoly> fs{sk->GetPrivateElement()};
        fs.back().SetFormat(Format::COEFFICIENT);

        fs.reserve(threshold);
        typename DCRTPoly::DugType dug;
        for (size_t t = 1; t < threshold; ++t)
            fs.emplace_back(dug, elementParams, Format::COEFFICIENT);

        const usint Ndim = elementParams->GetRingDimension();

        for (uint32_t pid = 1; pid <= N; ++pid) {
            // map pid -> (i,j): i in {0,1}, j in [0, floor((N-1)/2)]
            const uint32_t idx  = pid - 1;
            const uint32_t iBit = (idx & 1u);            // 0 -> +, 1 -> -
            const uint64_t jExp = static_cast<uint64_t>(idx >> 1); // 0,0,1,1,2,2,...

            DCRTPoly feval(elementParams, Format::COEFFICIENT, true);

            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();

                // start with constant term f0
                NativePoly acc(params_k, Format::COEFFICIENT, true);
                acc += fs[0].GetElementAtIndex(k);

                // accumulate f_t * α^{t}, where α = (-1)^i * X^j
                const auto& f0 = fs[0].GetElementAtIndex(k); (void)f0;
                for (size_t t = 1; t < threshold; ++t) {
                    const uint64_t e   = jExp * static_cast<uint64_t>(t); // exponent on X
                    const uint64_t r   = static_cast<uint64_t>(e % Ndim); // shift
                    const bool wrap    = ((e / Ndim) & 1ULL) != 0ULL;     // negacyclic wrap
                    const bool sign_it = ((iBit & 1u) && (t & 1u));        // (-1)^{i*t}
                    const bool neg     = (wrap ^ sign_it);                 // total sign flip

                    const auto& coeff_poly = fs[t].GetElementAtIndex(k);
                    NativePoly rotated(params_k, Format::COEFFICIENT, true);

                    // multiply coeff_poly by X^r mod (X^n + 1) with sign on wrap
                    for (size_t j = 0; j < Ndim; ++j) {
                        const auto cj = coeff_poly[j];
                        if (cj == NativeInteger(0))
                            continue;

                        size_t sum = j + r;
                        bool doWrap = (sum >= Ndim);
                        size_t idx2 = doWrap ? (sum - Ndim) : sum;

                        auto val = cj;
                        if (doWrap) // X^{j+r} -> -X^{j+r-n}
                            val = modq_k - val;

                        rotated[idx2] += val;
                    }

                    // apply (-1)^{i*t} combined with wrap parity
                    if (neg) {
                        for (size_t j = 0; j < Ndim; ++j) {
                            if (rotated[j] != NativeInteger(0))
                                rotated[j] = modq_k - rotated[j];
                        }
                    }

                    acc += rotated;
                }

                feval.SetElementAtIndex(k, std::move(acc));
            }

            SecretShares.emplace(pid, std::move(feval));
        }
    }
    // -------------------------
    // 2adic  (shares with f(-1) = s)
    // -------------------------
    else if (shareType == "2adic") {
        // Build f(x) = a0 + a1 x + ... + a_{t-1} x^{t-1}
        // Choose a1..a_{t-1} at random; set a0 so that f(-1) = s:
        // a0 = s - sum_{t=1}^{T-1} a_t * (-1)^t
        std::vector<DCRTPoly> fs;
        fs.reserve(threshold);
        typename DCRTPoly::DugType dug;

        // Placeholder for a0
        fs.emplace_back(DCRTPoly(elementParams, Format::COEFFICIENT, true));

        // Random a1..a_{T-1}
        for (size_t t = 1; t < threshold; ++t)
            fs.emplace_back(dug, elementParams, Format::COEFFICIENT);

        // Preload s in COEFFICIENT once
        DCRTPoly s_elem = sk->GetPrivateElement();
        s_elem.SetFormat(Format::COEFFICIENT);

        // Compute a0 per CRT tower/component
        DCRTPoly a0(elementParams, Format::COEFFICIENT, true);
        for (size_t k = 0; k < elementParams->GetParams().size(); ++k) {
            auto params_k = elementParams->GetParams()[k];
            auto modq_k   = params_k->GetModulus();

            const auto& s_k = s_elem.GetElementAtIndex(k);
            usint len = s_k.GetLength();

            NativePoly a0_poly(params_k, Format::COEFFICIENT, true);
            for (usint j = 0; j < len; ++j) {
                NativeInteger val = s_k[j];
                for (size_t t = 1; t < threshold; ++t) {
                    const auto& at_poly = fs[t].GetElementAtIndex(k);
                    const NativeInteger coeff = at_poly[j];
                    if ((t & 1u) == 1u) {
                        // odd t: (-1)^t = -1 => a0 += a_t
                        val = val.ModAdd(coeff, modq_k);
                    } else {
                        // even t: (-1)^t = +1 => a0 -= a_t
                        val = (val >= coeff) ? (val - coeff) : (val + modq_k - coeff);
                    }
                }
                a0_poly[j] = val;
            }
            a0.SetElementAtIndex(k, std::move(a0_poly));
        }
        fs[0] = std::move(a0);

        // Public points α_pid = X^{h * pid} in R_Q with X^n = -1
        const usint Ndim = elementParams->GetRingDimension();
        uint64_t M = 1;
        while (M < static_cast<uint64_t>(N)) M <<= 1;
        const uint64_t h = (2ULL * static_cast<uint64_t>(Ndim)) / M;

        for (size_t pid = 1; pid <= N; ++pid) {
            DCRTPoly feval(elementParams, Format::COEFFICIENT, true);

            for (size_t k = 0; k < vecSize; ++k) {
                auto params_k = elementParams->GetParams()[k];
                auto modq_k   = params_k->GetModulus();

                NativePoly fevalpoly(params_k, Format::COEFFICIENT, true);
                fevalpoly += fs[0].GetElementAtIndex(k); // constant term a0

                const unsigned __int128 sigma =
                    static_cast<unsigned __int128>(h) * static_cast<unsigned __int128>(pid);

                for (size_t t = 1; t < threshold; ++t) {
                    const unsigned __int128 e = sigma * static_cast<unsigned __int128>(t); // e = σ·t
                    const uint64_t r  = static_cast<uint64_t>(e % Ndim);                  // rotation
                    const bool neg    = ((e / Ndim) & 1ULL) != 0ULL;                      // global sign

                    const auto& coeff_poly = fs[t].GetElementAtIndex(k);
                    NativePoly rotated(params_k, Format::COEFFICIENT, true);

                    // Rotate coeff_poly by r in negacyclic ring (X^N = -1)
                    for (size_t j = 0; j < Ndim; ++j) {
                        const auto cj = coeff_poly[j];
                        if (cj == NativeInteger(0)) continue;

                        size_t sum = j + r;
                        bool wrap  = (sum >= Ndim);
                        size_t idx = wrap ? (sum - Ndim) : sum;

                        auto val = cj;
                        if (wrap) val = modq_k - val; // sign flip on wrap
                        rotated[idx] += val;
                    }

                    // Apply (-1)^{floor(e/N)}
                    if (neg) {
                        for (size_t j = 0; j < Ndim; ++j) {
                            if (rotated[j] != NativeInteger(0))
                                rotated[j] = modq_k - rotated[j];
                        }
                    }

                    fevalpoly += rotated;
                }

                feval.SetElementAtIndex(k, std::move(fevalpoly));
            }

            SecretShares.emplace(pid, std::move(feval));
        }
    }
    return SecretShares;
}


// ============================================================================

template <>
void CryptoContextImpl<DCRTPoly>::RecoverSharedKeyDealer(
    PrivateKey<DCRTPoly>& sk,
    std::unordered_map<uint32_t, DCRTPoly>& sk_shares,
    uint32_t N, uint32_t threshold,
    const std::string& shareType) const {

    if (sk_shares.size() < threshold)
        OPENFHE_THROW("Number of shares available less than threshold");

    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 2 for recovery");

    // temporary disabled to allow small T
    // if (threshold <= N / 2)
    //     OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto& cryptoParams  = sk->GetCryptoContext()->GetCryptoParameters();
    const auto& elementParams = cryptoParams->GetElementParams();
    size_t ring_dimension     = elementParams->GetRingDimension();
    size_t vecSize            = elementParams->GetParams().size();


    for (size_t k = 0; k < vecSize; k++) {
        auto modq_k = elementParams->GetParams()[k]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N must be less than DCRTPoly modulus");
    }

    // collect available indices
    std::vector<uint32_t> client_indexes;
    client_indexes.reserve(N);
    for (uint32_t i = 1; i <= N; ++i) {
        if (sk_shares.find(i) != sk_shares.end())
            client_indexes.push_back(i);
    }
    const uint32_t L = client_indexes.size();
    if (L < threshold)
        OPENFHE_THROW("Not enough shares to recover secret");

    // -------------------------
    // additive (N-of-N)
    // -------------------------
    if (shareType == "additive") {
        DCRTPoly sum_of_elems(elementParams, Format::EVALUATION, true);
        for (uint32_t i = 0; i < L; ++i) // additive dealer = N-of-N
            sum_of_elems += sk_shares.at(client_indexes[i]);
        sk->SetPrivateElement(std::move(sum_of_elems));
    }

    // -------------------------
    // shamir (standard)
    // -------------------------
    else if (shareType == "shamir") {
        std::vector<DCRTPoly> Lagrange_coeffs(L, DCRTPoly(elementParams, Format::EVALUATION));

        // build L_j(0) in each CRT tower
        for (uint32_t j = 0; j < L; j++) {
            auto cj = client_indexes[j];
            for (size_t k = 0; k < vecSize; k++) {
                auto modq_k = elementParams->GetParams()[k]->GetModulus();
                NativePoly multpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
                multpoly.AddILElementOne();
                for (uint32_t i = 0; i < L; i++) {
                    auto ci = client_indexes[i];
                    if (ci != cj) {
                        auto&& denominator = (cj < ci) ? NativeInteger(ci - cj)
                                                       : modq_k - NativeInteger(cj - ci);
                        auto denom_inv{denominator.ModInverse(modq_k)};
                        for (size_t d = 0; d < ring_dimension; ++d)
                            multpoly[d].ModMulFastEq(NativeInteger(ci).ModMul(denom_inv, modq_k), modq_k);
                    }
                }
                multpoly.SetFormat(Format::EVALUATION);
                Lagrange_coeffs[j].SetElementAtIndex(k, std::move(multpoly));
            }
            Lagrange_coeffs[j].SetFormat(Format::COEFFICIENT);
        }

        DCRTPoly lagrange_sum_of_elems(elementParams, Format::COEFFICIENT, true);
        for (size_t k = 0; k < vecSize; ++k) {
            NativePoly lagrange_sum_of_elems_poly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
            for (uint32_t i = 0; i < L; ++i) {
                const auto& coeff = Lagrange_coeffs[i].GetAllElements()[k];
                const auto& share = sk_shares.at(client_indexes[i]).GetAllElements()[k];
                lagrange_sum_of_elems_poly += coeff.TimesNoCheck(share);
            }
            lagrange_sum_of_elems.SetElementAtIndex(k, std::move(lagrange_sum_of_elems_poly));
        }
        lagrange_sum_of_elems.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(std::move(lagrange_sum_of_elems));
    }
    // -------------------------
    // BFM+25 reconstruction (at x = 0)
    // L_j(0) = ∏_{i≠j} (-α_i) * (α_j - α_i)^{-1} in R_Q
    // α_{(i,j)} = (-1)^i * X^j, all inverses/component-wise in EVALUATION format per tower.
    // -------------------------
    else if (shareType == "BFM+25") {
        const auto& params = elementParams;
        const usint Ndim   = params->GetRingDimension();

        // gather available client indexes
        std::vector<uint32_t> idxs;
        idxs.reserve(sk_shares.size());
        for (auto& kv : sk_shares)
            idxs.push_back(kv.first);

        const size_t L = idxs.size();
        if (L < threshold)
            OPENFHE_THROW("Not enough shares to recover secret");

        // build α_j for each available share index
        std::vector<DCRTPoly> alphas;
        alphas.reserve(L);
        for (size_t u = 0; u < L; ++u) {
            const uint32_t pid = idxs[u];
            const uint32_t idx = pid - 1;
            const uint32_t iBit = (idx & 1u);
            const uint64_t jExp = static_cast<uint64_t>(idx >> 1);

            DCRTPoly alpha(params, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = params->GetParams()[k];
                auto modq_k = pk->GetModulus();

                NativePoly mono(pk, Format::COEFFICIENT, true);
                // place ±X^{jExp}: set coefficient at index jExp with ±1
                const size_t r = static_cast<size_t>(jExp % Ndim);
                mono[r] = (iBit ? (modq_k - 1) : NativeInteger(1));
                alpha.SetElementAtIndex(k, std::move(mono));
            }
            alphas.emplace_back(std::move(alpha));
        }

        // construct L_j(0) via products in EVALUATION domain
        std::vector<DCRTPoly> Ljs;
        Ljs.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly Lj(params, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk = params->GetParams()[k];
                NativePoly one(pk, Format::COEFFICIENT, true);
                one[0] = NativeInteger(1);
                Lj.SetElementAtIndex(k, std::move(one));
            }
            Lj.SetFormat(Format::EVALUATION);

            for (size_t i = 0; i < L; ++i) if (i != j) {
                DCRTPoly negAlphaI = alphas[i].Negate();   // (-α_i)
                DCRTPoly denom     = alphas[j].Minus(alphas[i]); // (α_j - α_i)

                negAlphaI.SetFormat(Format::EVALUATION);
                denom.SetFormat(Format::EVALUATION);

                // component-wise inverse of denom
                DCRTPoly denomInvEval(params, Format::EVALUATION, true);
                for (size_t k = 0; k < vecSize; ++k) {
                    auto       pk     = params->GetParams()[k];
                    auto       modq_k = pk->GetModulus();
                    const auto& den_k = denom.GetElementAtIndex(k);
                    auto       vals   = den_k.GetValues();
                    usint      len    = vals.GetLength();

                    NativeVector invVals(len, modq_k);
                    for (usint s = 0; s < len; ++s) {
                        // α_j - α_i are invertible by construction of public points
                        invVals[s] = vals[s].ModInverse(modq_k);
                    }
                    NativePoly invPoly(pk, Format::EVALUATION, true);
                    invPoly.SetValues(std::move(invVals), Format::EVALUATION);
                    denomInvEval.SetElementAtIndex(k, std::move(invPoly));
                }

                Lj *= negAlphaI;
                Lj *= denomInvEval;
            }

            Lj.SetFormat(Format::COEFFICIENT);
            Ljs.emplace_back(std::move(Lj));
        }

        // s = Σ_j L_j(0) * share_j
        DCRTPoly s_rec(params, Format::COEFFICIENT, true);
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly LjEval = Ljs[j];                       LjEval.SetFormat(Format::EVALUATION);
            DCRTPoly shEval = sk_shares.at(idxs[j]);        shEval.SetFormat(Format::EVALUATION);
            DCRTPoly term   = LjEval * shEval;
            term.SetFormat(Format::COEFFICIENT);
            s_rec += term;
        }

        s_rec.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(std::move(s_rec));
    }
    // -------------------------
    // 2adic  (reconstruct at x = -1)
    // -------------------------
    else if (shareType == "2adic") {
        const auto& params = elementParams;
        const usint Ndim   = params->GetRingDimension();
        const uint64_t two_n = 2ULL * static_cast<uint64_t>(Ndim);

        uint64_t M = 1;
        while (M < static_cast<uint64_t>(N)) M <<= 1;
        if (two_n % M != 0ULL)
            OPENFHE_THROW("2-adic: M must divide 2n.");

        const uint64_t h = two_n / M;

        // α_j = X^{h * cid_j}
        std::vector<DCRTPoly> alphas;
        alphas.reserve(L);
        for (size_t j = 0; j < L; ++j) {
            const uint64_t cid   = static_cast<uint64_t>(client_indexes[j]);
            const unsigned __int128 sigma = static_cast<unsigned __int128>(h) * cid;

            const uint64_t r       = static_cast<uint64_t>(sigma % Ndim);
            const bool     negWrap = (static_cast<unsigned __int128>(sigma / Ndim) & 1) != 0;

            DCRTPoly alpha(params, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = params->GetParams()[k];
                auto modq_k = pk->GetModulus();

                NativePoly mono(pk, Format::COEFFICIENT, true);
                mono[r] = negWrap ? (modq_k - 1) : NativeInteger(1); // ±X^r
                alpha.SetElementAtIndex(k, std::move(mono));
            }
            alphas.emplace_back(std::move(alpha));
        }

        std::vector<DCRTPoly> Ljs;
        Ljs.reserve(L);

        // L_j(-1) = ∏_{i≠j} ( -1 - α_i ) * (α_j - α_i)^{-1}
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly NumeratorEval(params, Format::COEFFICIENT, true);
            DCRTPoly DenominatorEval(params, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk = params->GetParams()[k];
                NativePoly one(pk, Format::COEFFICIENT, true);
                one[0] = NativeInteger(1);
                NumeratorEval.SetElementAtIndex(k, one);
                DenominatorEval.SetElementAtIndex(k, one);
            }

            // Build (-1) in COEFFICIENT
            DCRTPoly minusOneCoeff(params, Format::COEFFICIENT, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto pk     = params->GetParams()[k];
                auto modq_k = pk->GetModulus();
                NativePoly c(pk, Format::COEFFICIENT, true);
                c[0] = modq_k - NativeInteger(1); // -1 mod q
                minusOneCoeff.SetElementAtIndex(k, std::move(c));
            }

            for (size_t i = 0; i < L; ++i) {
                if (i == j) continue;

                // Build in COEFFICIENT
                DCRTPoly x0MinusAlphaI = minusOneCoeff - alphas[i];   // (-1 - α_i)
                DCRTPoly denom         = alphas[j].Minus(alphas[i]);  // (α_j - α_i)

                // Move to EVALUATION for component-wise ops
                x0MinusAlphaI.SetFormat(Format::EVALUATION);
                denom.SetFormat(Format::EVALUATION);
                NumeratorEval.SetFormat(Format::EVALUATION);
                DenominatorEval.SetFormat(Format::EVALUATION);

                NumeratorEval   *= x0MinusAlphaI;
                DenominatorEval *= denom;
            }

            // Component-wise inverse of DenominatorEval
            DCRTPoly DenInvEval(params, Format::EVALUATION, true);
            for (size_t k = 0; k < vecSize; ++k) {
                auto& den_k  = DenominatorEval.GetElementAtIndex(k);
                auto  vals   = den_k.GetValues();
                auto  pk     = params->GetParams()[k];
                auto  modq_k = pk->GetModulus();
                usint len    = vals.GetLength();

                NativeVector invVals(len, modq_k);
                for (usint s = 0; s < len; ++s)
                    invVals[s] = vals[s].ModInverse(modq_k);

                NativePoly invPoly(pk, Format::EVALUATION, true);
                invPoly.SetValues(std::move(invVals), Format::EVALUATION);
                DenInvEval.SetElementAtIndex(k, std::move(invPoly));
            }

            DCRTPoly Lj = NumeratorEval * DenInvEval;
            Lj.SetFormat(Format::COEFFICIENT);
            Ljs.emplace_back(std::move(Lj));
        }

        // s = Σ_j L_j(-1) * share_j
        DCRTPoly s_rec(params, Format::COEFFICIENT, true);
        for (size_t j = 0; j < L; ++j) {
            DCRTPoly LjEval = Ljs[j];                                  LjEval.SetFormat(Format::EVALUATION);
            DCRTPoly shEval = sk_shares.at(client_indexes[j]);          shEval.SetFormat(Format::EVALUATION);
            DCRTPoly term   = LjEval * shEval;
            term.SetFormat(Format::COEFFICIENT);
            s_rec += term;
        }

        s_rec.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(std::move(s_rec));
    }


}

// explicit template instantiations (including the instantiations reqiured for pybind11 binding)
// clang-format off
template class CryptoContextImpl<DCRTPoly>;

#define INSTANTIATE_FUNCTION_TEMPLATES(VECTOR_TYPE) \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalChebyshevSeries<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesLinear<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesPS<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalLinearWSum<VECTOR_TYPE>(std::vector<ReadOnlyCiphertext<DCRTPoly>>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalLinearWSumMutable<VECTOR_TYPE>(const std::vector<VECTOR_TYPE>&, std::vector<Ciphertext<DCRTPoly>>&) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalPoly<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalPolyLinear<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalPolyPS<VECTOR_TYPE>(ConstCiphertext<DCRTPoly>&, const std::vector<VECTOR_TYPE>&) const;

INSTANTIATE_FUNCTION_TEMPLATES(int64_t)
INSTANTIATE_FUNCTION_TEMPLATES(double)
INSTANTIATE_FUNCTION_TEMPLATES(std::complex<double>)
// clang-format on

}  // namespace lbcrypto




