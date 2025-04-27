#pragma once

#include "cert_validator_intf.h"

namespace Cryptix {

class SingleCertValidator : public ICertValidator {
public:
    bool Verify(X509_STORE* store, Cert& cert) override {
        ::X509_STORE_CTX* storeCtx = ::X509_STORE_CTX_new();
        if (::X509_STORE_CTX_init(storeCtx, store, cert.Get(), nullptr) != 1) {
            return false;
        }

        int res = ::X509_verify_cert(storeCtx);
        ::X509_STORE_CTX_free(storeCtx);

        if (res != 1) {
            // any error msg process here.
            return false;
        }

        return true;
    }
};

}