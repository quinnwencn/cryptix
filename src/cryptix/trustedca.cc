#include "cryptix/trustedca.h"

#include <openssl/err.h>
#include <fmt/core.h>

#include "cryptix/error.h"

namespace Cryptix {

std::optional<TrustedCa> TrustedCa::FromTrustedCACert(Cert& trustedCaCert) {
    if (!trustedCaCert.IsCA()) {
        CRYPTX_ERROR("Not CA");
        return std::nullopt;
    }

    std::shared_ptr<::X509_STORE> st (::X509_STORE_new(), ::X509_STORE_free);
    if (st == nullptr) {
        CRYPTX_ERROR("Allocate x509 store failed.");
        return std::nullopt;
    }

    if (::X509_STORE_add_cert(st.get(), trustedCaCert.Get()) != 1) {
        CRYPTX_ERROR(fmt::format("Add cert failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return std::nullopt;
    }
    return TrustedCa(st);
}

}