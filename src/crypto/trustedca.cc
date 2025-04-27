#include "cryptix/trustedca.h"

namespace Cryptix {

std::optional<TrustedCa> TrustedCa::FromTrustedCACert(Cert& trustedCaCert) {
    if (!trustedCaCert.IsCA()) {
        return std::nullopt;
    }

    std::shared_ptr<::X509_STORE> st (::X509_STORE_new(), ::X509_STORE_free);
    if (st == nullptr) {
        return std::nullopt;
    }

    if (::X509_STORE_add_cert(st.get(), trustedCaCert.Get()) != 1) {
        return std::nullopt;
    }
    return TrustedCa(st);
}

}