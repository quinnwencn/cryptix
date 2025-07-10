//
// Created by quinn on 7/4/2025.
// Copyright (c) 2025 All rights reserved.
//
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "cryptix/key_param.h"
#include "cryptix/error.h"

namespace Cryptix {

namespace {

const std::unordered_map<EccCurve, int> ECC_CURVES {
    {EccCurve::ed25519,      NID_ED25519},
    {EccCurve::ed448,        NID_ED448},
    {EccCurve::secp256k1,    NID_secp256k1},
    {EccCurve::secp256r1,    NID_X9_62_prime256v1},
    {EccCurve::secp384r1,    NID_secp384r1},
    {EccCurve::secp521r1,    NID_secp521r1},
    {EccCurve::brainpoolP256r1, NID_brainpoolP256r1},
    {EccCurve::brainpoolP384r1, NID_brainpoolP384r1},
    {EccCurve::brainpoolP512r1, NID_brainpoolP512r1},
    {EccCurve::curve25519,   NID_X25519},
    {EccCurve::x448,         NID_X448}
    };

}

bool RsaKeyParam::Apply(EVP_PKEY_CTX* ctx) const {
    if (ctx == nullptr) {
        CRYPTIX_ERROR("ctx nullptr");
        return false;
    }

    return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(size_));
}

bool EccKeyParam::Apply(EVP_PKEY_CTX* ctx) const {
    if (ctx == nullptr) {
        CRYPTIX_ERROR("ctx nullptr");
        return false;
    }

    if (ECC_CURVES.find(curve_) == ECC_CURVES.end()) {
        CRYPTIX_ERROR("Unknown curve");
        return false;
    }

    return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ECC_CURVES.at(curve_));
}

}
