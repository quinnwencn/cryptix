#include "cryptix/trustedca.h"

namespace Cryptix {

std::optional<TrustedCa> TrustedCa::FromTrustedCACert(std::shared_ptr<Cert> trustedCaCert) {
    if (trustedCaCert == nullptr) {
        return std::nullopt;
    }

    if (!trustedCaCert.IsCA()) {
        return std::nullopt;
    }

    auto st = std::make_shared<::X509_STORE>(::X509_STORE_new(), ::X509_STORE_free);
    if (st == nullptr) {
        return std::nullopt;
    }

    return TrustedCa(st);
}

}