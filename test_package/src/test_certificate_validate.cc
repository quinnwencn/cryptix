#include "cryptix/cert.h"
#include "cryptix/trustedca.h"
#include "cryptix/cert_validator_intf.h"
#include "cryptix/cert_verifier.h"
#include "cryptix/single_cert_validator.h"
#include "cryptix/chain_cert_validator.h"

#include <gtest/gtest.h>

using namespace Cryptix;

TEST(TrustCaTest, ConstructTest) {
    auto caCert = Cert::FromPemFile(ROOT_PEM);
    EXPECT_TRUE(caCert.has_value());
    auto ca = TrustedCa::FromTrustedCACert(caCert.value());
    EXPECT_TRUE(ca.has_value());

    auto intermediateCert = Cert::FromPemFile(INTERMEDIA_CERT);
    EXPECT_TRUE(intermediateCert.has_value());
    auto intermediate = TrustedCa::FromTrustedCACert(intermediateCert.value());
    EXPECT_TRUE(intermediate.has_value());

    
    auto endCert = Cert::FromPemFile(END_CERT);
    EXPECT_TRUE(endCert.has_value());
    auto end = TrustedCa::FromTrustedCACert(endCert.value());
    EXPECT_FALSE(end.has_value());
}