//
// Created by quinn on 7/9/2025.
// Copyright (c) 2025 All rights reserved.
//

#include <fmt/core.h>
#include <cpputils/fileops.h>

#include "cryptix/error.h"
#include "cryptix/certificate_validator.h"
#include "cryptix/cert.h"

namespace Cryptix {

CertificateValidator::CertificateValidator(const std::vector<std::vector<uint8_t>>& trustedCerts)
	: x509Store_(UniqueX509Store(::X509_STORE_new(), ::X509_STORE_free)) {
	for (const auto& trustedCert : trustedCerts) {
        auto trusted = Cert::FromPemVector(trustedCert);
        if (!trusted.has_value()) {
            throw std::runtime_error("Can't create trusted from given certs");
        }

        ::X509_STORE_add_cert(x509Store_.get(), trusted.value().Get());
    }
}

std::vector<uint8_t> CertificateValidator::LoadCertificate(const std::filesystem::path& certPath) {
	return Cpputils::ReadFile2Vec(certPath);
}

bool CertificateValidator::Validate(const std::vector<uint8_t>& certificate) {
	if (certificate.empty()) {
		CRYPTIX_ERROR("cert empty");
		return false;
	}

	if (x509Store_ == nullptr) {
		CRYPTIX_ERROR("Validator nullptr");
		return false;
	}

    auto cert = Cert::FromPemVector(certificate);
    if (!cert.has_value()) {
        CRYPTIX_ERROR("can not load cert from vector");
        return false;
    }

    return Validate(cert.value());
}

bool CertificateValidator::Validate(const Cert& cert) {
    auto ctx = UniqueX509StoreCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (ctx == nullptr) {
        CRYPTIX_ERROR("Create x509 store ctx failed.");
        return false;
    }

    ::X509_STORE_CTX_init(ctx.get(), x509Store_.get(), cert.Get(), nullptr);
    int verifyResult = ::X509_verify_cert(ctx.get());
    if (verifyResult == 1) {
        return true;
    }

    CRYPTIX_ERROR(fmt::format("Certificate verify failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
    return false;
}

bool CertificateValidator::Validate(const std::vector<std::vector<uint8_t>>& chainCertificates) {
	if (chainCertificates.empty()) {
		CRYPTIX_ERROR("cert empty");
		return false;
	}

    STACK_OF(X509)* certStack = sk_X509_new_null();
    if (certStack == nullptr) {
        CRYPTIX_ERROR(fmt::format("Allocate cert stack failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return false;
    }

    for (const auto& certData : chainCertificates) {
        auto bio = UniqueBio { BIO_new_mem_buf(certData.data(), certData.size()), BIO_free };
        auto cert = Cert::FromPemVector(certData);
        if (!cert.has_value()) {
            sk_X509_free(certStack);
            CRYPTIX_ERROR("can not load cert from certData");
            return false;
        }

        if (::X509_up_ref(cert.value().Get()) != 1) {
            sk_X509_free(certStack);
            CRYPTIX_ERROR("Increase ref num failed, double free!!!");
            return false;
        }
        sk_X509_push(certStack, cert.value().Get());
    }

    if (sk_X509_num(certStack) == 0) {
        CRYPTIX_ERROR("No valid certificates in chain");
        sk_X509_free(certStack);
        return false;
    }

    auto ctx = UniqueX509StoreCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (ctx == nullptr) {
        CRYPTIX_ERROR("Create x509 store ctx failed.");
        sk_X509_free(certStack);
        return false;
    }

    X509* leafCert = sk_X509_value(certStack, 0);
    if (::X509_STORE_CTX_init(ctx.get(), x509Store_.get(), leafCert, certStack) != 1) {
        CRYPTIX_ERROR(fmt::format("Init X509 store ctx failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        sk_X509_free(certStack);
        return false;
    }
    int verifyResult = ::X509_verify_cert(ctx.get());
    if (verifyResult == 1) {
        sk_X509_free(certStack);
        return true;
    }

    sk_X509_free(certStack);
    CRYPTIX_ERROR(fmt::format("Certificate verify failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
    return false;
}

}
