//
// Created by quinn on 7/9/2025.
// Copyright (c) 2025 All rights reserved.
//

#ifndef CERTIFICATE_VALIDATOR_H
#define CERTIFICATE_VALIDATOR_H

#include <vector>
#include <string>
#include <filesystem>

#include "_common.h"
#include "cert.h"

namespace Cryptix {

class CertificateValidator {
public:
    CertificateValidator(const std::vector<std::vector<uint8_t>>& trustedCerts);

    static std::vector<uint8_t> LoadCertificate(const std::filesystem::path& certPath);

    bool Validate(const std::vector<uint8_t>& certificate);
    bool Validate(const Cert& cert);
    bool Validate(const std::vector<std::vector<uint8_t>>& chainCertificate);

private:
    UniqueX509Store x509Store_;
};

}

#endif //CERTIFICATE_VALIDATOR_H
