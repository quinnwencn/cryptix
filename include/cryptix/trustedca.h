#pragma once

#include <memory>
#include <openssl/x509.h>

#include "cert.h"

namespace Cryptix {

class TrustedCa {
public:
    static std::optional<TrustedCa> FromTrustedCACert(std::shared_ptr<Cert> trustedCaCert);
    ~TrustedCa() = default;

    ::X509_STORE* GetStore() const { return store_.get(); }

private:
    TrustedCa(std::shared_ptr<::X509_STORE> st) : store_(st) {}

private:
    std::shared_ptr<::X509_STORE> store_;
};

}
