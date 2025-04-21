#include "cryptix/cert.h"

#include <gtest/gtest.h>

using namespace Cryptix;

TEST(CertTest, ConstructTest) {
    auto cert = Cert::FromPemFile(ROOT_PEM);
    EXPECT_TRUE(cert.has_value());
}