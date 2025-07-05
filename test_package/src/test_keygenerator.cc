//
// Created by quinn on 7/3/2025.
// Copyright (c) 2025 All rights reserved.
//
#include "cryptix/keygenerator.h"
#include "cryptix/key_param.h"

#include <gtest/gtest.h>

using namespace Cryptix;

namespace {
    void GenerateKeyPairs(KeyStore source, const KeyParam& keyParam) {
        auto keyGen = KeyGenerator(source);
        std::string keyPath = "/tmp/test_keypair";
        auto key = keyGen.GenerateKeyPairs(keyPath, keyParam);
        EXPECT_NE(nullptr, key);
        auto publicKeyPath = keyPath + "_pub.pem";
        auto privateKeyPath = keyPath + "_priv.pem";
        EXPECT_TRUE(std::filesystem::exists(publicKeyPath));
        EXPECT_TRUE(std::filesystem::exists(privateKeyPath));
        std::filesystem::remove(publicKeyPath);
        std::filesystem::remove(privateKeyPath);

        EXPECT_FALSE(std::filesystem::exists(publicKeyPath));
        EXPECT_FALSE(std::filesystem::exists(privateKeyPath));
    }
}

TEST(KeyGenTest, GenerateKeyPairsInHsmTest) {
    auto keyGen = KeyGenerator(KeyStore::Hsm);
    EXPECT_THROW(keyGen.GenerateKeyPairs("test", RsaKeyParam(RsaKeySize::RSA2048)), std::runtime_error);
    EXPECT_THROW(keyGen.GenerateKeyPairs("test", EccKeyParam(EccCurve::ed25519)), std::runtime_error);
}

TEST(KeyGenTest, GenerateKeyPairsInFilesystemTest) {
    GenerateKeyPairs(KeyStore::Filesystem, RsaKeyParam(RsaKeySize::RSA1024));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::ed25519));
}

TEST(KeyGenTest, GenerateKeyPairsWithKeySizesTest) {
    // RSA
    GenerateKeyPairs(KeyStore::Filesystem, RsaKeyParam(RsaKeySize::RSA1024));
    GenerateKeyPairs(KeyStore::Filesystem, RsaKeyParam(RsaKeySize::RSA2048));
    GenerateKeyPairs(KeyStore::Filesystem, RsaKeyParam(RsaKeySize::RSA3072));
    GenerateKeyPairs(KeyStore::Filesystem, RsaKeyParam(RsaKeySize::RSA4096));

    // ECC
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::ed25519));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::ed448));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::secp256k1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::secp256r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::secp384r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::secp521r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::brainpoolP256r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::brainpoolP384r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::brainpoolP512r1));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::curve25519));
    GenerateKeyPairs(KeyStore::Filesystem, EccKeyParam(EccCurve::x448));
}
