#include "cryptix/cert.h"

#include <gtest/gtest.h>
#include <cpputils/fileops.h>

using namespace Cryptix;

TEST(CertTest, ConstructFromPemFileTest) {
    auto cert = Cert::FromPemFile(ROOT_PEM);
    EXPECT_TRUE(cert.has_value());
}

TEST(CertTest, ConstructFromPemContentTest) {
	auto content = Cpputils::ReadFile(ROOT_PEM);
	auto certOp = Cert::FromPemText(content);
	EXPECT_TRUE(certOp.has_value());
}

TEST(CertTest, ConstructFromPemVec) {
	auto vec = Cpputils::ReadFile2Vec(ROOT_PEM);
	EXPECT_FALSE(vec.empty());

	auto certOp = Cert::FromPemVector(vec);
	EXPECT_TRUE(certOp.has_value());
}
