#pragma once

#include <memory>
#include <openssl/x509.h>

#include "cert.h"
#include "trustedca.h"
#include "cert_validator_intf.h"

namespace Cryptix {

class CertVerifier {
public:
    CertVerifier(TrustedCa& tc) : tc_(tc) {}

    bool Verify(ICertValidator& cv, Cert& cert) {
        return cv.Verify(tc_.GetStore(), cert);
    }

private:
    TrustedCa tc_;
};

}
