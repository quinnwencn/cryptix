//
// Created by quinn on 7/4/2025.
// Copyright (c) 2025 All rights reserved.
//

#include <unordered_map>
#include <openssl/obj_mac.h>

#include "cryptix/keygenerator.h"

namespace Cryptix {

UniqueEvpKey KeyGenerator::GenerateKeyPairs(const std::string& keyId, const KeyParam& keyParam) {
    if (store_ == KeyStore::Hsm) {
        throw std::runtime_error("Hsm support not implemented yet.");
    }

    auto ctx = UniqueEvpPkeyCtx(::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), ::EVP_PKEY_CTX_free);
    if (ctx == nullptr) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }

    if (::EVP_PKEY_keygen_init(ctx.get()) != 1) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }

    if (!keyParam.Apply(ctx.get())) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }

    ::EVP_PKEY* pkey {nullptr};
    if (::EVP_PKEY_keygen(ctx.get(), &pkey) != 1) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }

    UniqueEvpKey keyPair(pkey, ::EVP_PKEY_free);

    auto publicKey = keyId + "_pub.pem";
    auto privateKey = keyId + "_priv.pem";
    std::filesystem::path parent = std::filesystem::path(publicKey).parent_path();
    if (!std::filesystem::exists(parent)) {
        std::filesystem::create_directories(parent);
    }

    if (!SavePublicKey(publicKey, keyPair.get())) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }

    if (!SavePrivateKey(privateKey, keyPair.get())) {
        return UniqueEvpKey(nullptr, ::EVP_PKEY_free);
    }
    return keyPair;
}

bool KeyGenerator::SavePublicKey(const std::filesystem::path& path, const EVP_PKEY* pkey) {
    UniqueBio bio (::BIO_new_file(path.c_str(), "w"), ::BIO_free);
    if (bio == nullptr) {
        return false;
    }

    if(::PEM_write_bio_PUBKEY(bio.get(), pkey) != 1) {
        return false;
    }

    return true;
}

bool KeyGenerator::SavePrivateKey(const std::filesystem::path& path, const EVP_PKEY* pkey) {
    UniqueBio bio (::BIO_new_file(path.c_str(), "w"), ::BIO_free);
    if (bio == nullptr) {
        return false;
    }

    if(::PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return false;
    }

    return true;
}

}
