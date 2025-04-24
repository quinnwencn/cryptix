#include "cryptix/privatekey.h"

#include <gtest/gtest.h>
#include <fstream>

using namespace Cryptix;

TEST(PrivateKeyTest, ConstructTest) {
    auto key = PrivateKey::FromKeyFile(ROOT_PRIV_KEY);
    EXPECT_TRUE(key.has_value());

    auto pkey = PrivateKey::FromKeyFile(ROOT_PUB_KEY);
    EXPECT_FALSE(pkey.has_value());

    std::ifstream ifs(ROOT_PRIV_KEY);
    EXPECT_TRUE(ifs.good());
    std::string keyContent((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto key2 = PrivateKey::FromKeyContent(keyContent);
    EXPECT_TRUE(key2.has_value());
}

TEST(PrivateKeyTest, EmptyDataSignTest) {
    auto keyOpt = PrivateKey::FromKeyFile(ROOT_PRIV_KEY);
    auto key = std::move(keyOpt.value());
    std::vector<uint8_t> data {};
    auto sig = key.Sign(data, SignAlgo::RSA_PKCS_V1_5);
    EXPECT_FALSE(sig.has_value());

    std::string strData {""};
    sig = key.Sign(strData, SignAlgo::RSA_PKCS_V1_5);
    EXPECT_FALSE(sig.has_value());
}

TEST(PrivateKeyTest, ValidDataSignTest) {
    auto keyOpt = PrivateKey::FromKeyFile(ROOT_PRIV_KEY);
    auto key = std::move(keyOpt.value());
    std::string strData {"hello, world!"};
    auto sig = key.Sign(strData, SignAlgo::RSA_PKCS_V1_5);
    EXPECT_TRUE(sig.has_value());
}