//
// Created by quinn on 7/3/2025.
// Copyright (c) 2025 All rights reserved.
//

#ifndef KEYGENERATOR_H
#define KEYGENERATOR_H

#include <string>
#include <filesystem>

#include "_common.h"
#include "key_param.h"

namespace Cryptix {

enum class KeyStore {
    Filesystem,
    Hsm,
};

class KeyGenerator {
public:
    KeyGenerator(KeyStore store) : store_(store) {}
    ~KeyGenerator() = default;

    UniqueEvpKey GenerateKeyPairs(const std::string& keyId, const KeyParam& keySize);

    bool SavePublicKey(const std::filesystem::path& path, const EVP_PKEY* pkey);
    bool SavePrivateKey(const std::filesystem::path& path, const EVP_PKEY* pkey);

protected:
    KeyStore store_;
};

}

#endif //KEYGENERATOR_H
