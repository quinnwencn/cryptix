#include "cryptix/privatekey.h"
#include "cpputils/string.h"

#include <gtest/gtest.h>
#include <fstream>

using namespace Cryptix;

class PrivateKeyTest : public ::testing::Test {
protected:
    void SetUp() override {
        key_ = BaseKey::FromPrivateKeyContent(Utils::ReadFileContent(ROOT_PRIV_KEY));
    }

    UniqueEvpKey key_;
};

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

TEST_F(PrivateKeyTest, HandlesEmptyData) {
    PrivateKey key(key_);
    EXPECT_EQ(key.Sign("", SignAlgo::RSA_PKCS_V1_5), std::nullopt);
}

TEST_F(PrivateKeyTest, HandlesEmptyKey) {
    PrivateKey key(nullptr);
    EXPECT_EQ(key.Sign("test", SignAlgo::RSA_PKCS_V1_5), std::nullopt);
}

TEST_F(PrivateKeyTest, SignWithPkcs1V15) {
    PrivateKey key(key_);
    auto sig = key.Sign("test", SignAlgo::RSA_PKCS_V1_5);
    EXPECT_TRUE(sig.has_value());
    EXPECT_FALSE(sig.value().empty());
}

TEST_F(PrivateKeyTest, SignWithRsaSsaPss) {
    PrivateKey key(key_);
    auto sig = key.Sign("test", SignAlgo::RSASSA_PSS);
    EXPECT_TRUE(sig.has_value());
    EXPECT_FALSE(sig.value().empty());
}

// TODO SignatureVerify

