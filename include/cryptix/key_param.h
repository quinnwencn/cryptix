//
// Created by quinn on 7/4/2025.
// Copyright (c) 2025 All rights reserved.
//

#ifndef KEYGENERATOR_PARAM_H
#define KEYGENERATOR_PARAM_H

#include <openssl/evp.h>

namespace Cryptix {

enum class EccCurve {
    // Edwards Curves (EdDSA)
    ed25519,
    ed448,

    // SECG/NIST Curves (ECDSA/ECDH)
    secp256k1,  // Bitcoin/SECP256K1
    secp256r1,  // NIST P-256
    secp384r1,  // NIST P-384
    secp521r1,  // NIST P-521

    // Brainpool Curves (RFC 5639)
    brainpoolP256r1,
    brainpoolP384r1,
    brainpoolP512r1,
    curve25519,
    x448
};

enum class RsaKeySize {
    RSA1024 = 1024,
    RSA2048 = 2048,
    RSA3072 = 3072,
    RSA4096 = 4096
};

class KeyParam {
public:
    KeyParam() = default;

    virtual bool Apply(EVP_PKEY_CTX* ctx) const = 0;
};

class RsaKeyParam : public KeyParam {
public:
    RsaKeyParam(RsaKeySize size) : size_(size) {}

    bool Apply(EVP_PKEY_CTX* ctx) const override;

private:
    RsaKeySize size_;
};

class EccKeyParam : public KeyParam {
public:
    EccKeyParam(EccCurve curve) : curve_(curve) {}

    bool Apply(EVP_PKEY_CTX* ctx) const override;

private:
    EccCurve curve_;
};

}

#endif //KEYGENERATOR_PARAM_H
