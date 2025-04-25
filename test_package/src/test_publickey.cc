#include "cryptix/publickey.h"

#include <gtest/gtest.h>

using namespace Cryptix;

TEST(PublicKeyTest, ConstructTest) {
    auto key = PublicKey::FromKeyFile(ROOT_PUB_KEY);
    EXPECT_TRUE(key.has_value);
}