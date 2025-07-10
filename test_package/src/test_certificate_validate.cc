#include "cryptix/cert.h"
#include "cryptix/certificate_validator.h"
#include "cryptix/error.h"

#include <gtest/gtest.h>

using namespace Cryptix;

TEST(CertificateValidatorTest, ConstructTest) {
	std::string errMsg {"Can't create trusted from given certs"};
	std::vector<std::vector<uint8_t>> trustedCerts {
		CertificateValidator::LoadCertificate(END_KEY),
		CertificateValidator::LoadCertificate(ROOT_PEM)
	};

	EXPECT_THROW(auto cv = CertificateValidator(trustedCerts), std::runtime_error);
}

TEST(CertificateValidatorTest, ValidateSingleCertifiate) {
	std::string errMsg {"Can't create trusted from given certs"};
	std::vector<std::vector<uint8_t>> trustedCerts {
		CertificateValidator::LoadCertificate(ROOT_PEM),
		CertificateValidator::LoadCertificate(INTERMEDIA_CERT)
	};

	auto certValidator = CertificateValidator(trustedCerts);
	auto endCertOp = Cert::FromPemFile(END_CERT);
	EXPECT_TRUE(endCertOp.has_value());

	EXPECT_TRUE(certValidator.Validate(endCertOp.value()));
}

TEST(CertficateValidatorTest, ValidateChainCertificate) {
	std::vector<std::vector<uint8_t>> trustedCerts {
		CertificateValidator::LoadCertificate(ROOT_PEM)
	};
	auto certValidator = CertificateValidator(trustedCerts);

	std::vector<std::vector<uint8_t>> chainCerts {
		CertificateValidator::LoadCertificate(INTERMEDIA_CERT),
		CertificateValidator::LoadCertificate(END_CERT)
	};

	EXPECT_TRUE(certValidator.Validate(chainCerts));
}

TEST(CertficateValidatorTest, ValidateInvalidChainCertificate) {
	std::vector<std::vector<uint8_t>> trustedCerts {
		CertificateValidator::LoadCertificate(ROOT_PEM)
	};
	auto certValidator = CertificateValidator(trustedCerts);

	std::vector<std::vector<uint8_t>> chainCerts {
		CertificateValidator::LoadCertificate(INTERMEDIA_CERT),
		CertificateValidator::LoadCertificate(END_KEY)
	};

	EXPECT_FALSE(certValidator.Validate(chainCerts));
}
