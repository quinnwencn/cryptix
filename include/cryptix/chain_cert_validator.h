#pragma once

#include <vector>
#include <exception>

#include "cert_validator_intf.h"

namespace Cryptix {

class ChainCertValidator : public ICertValidator {
private:
    class X509Stack {
    public:
        X509Stack() : stack_(sk_X509_new_null()) {
            if (stack_ == nullptr) {
                throw std::bad_alloc();
            }
        }

        ~X509Stack() {
            if (stack_ != nullptr) {
                sk_X509_free(stack_);
            }
        }

        bool AddCert(Cert& cert) {
            // increment ref count to avoid double free
            if (::X509_up_ref(cert.Get()) != 1) {
                return false;
            }

            if (sk_X509_push(stack_, cert.Get()) == 0) {
                return false;
            }

            return true;
        }
        
        STACK_OF(X509)* Get() const { return stack_; }

    private:
        STACK_OF(X509)* stack_ {nullptr};
    };

public:
    ChainCertValidator(std::vector<Cert>&& intermediates) : intermediates_(std::move(intermediates)) {}

    bool Verify(X509_STORE* store, Cert& cert) override {
        X509Stack chain;
        for (auto& cert : intermediates_) {
            if (!chain.AddCert(cert)) {
                return false;
            }
        }

        ::X509_STORE_CTX* storeCtx = ::X509_STORE_CTX_new();
        if (storeCtx == nullptr) {
            return false;
        }

        if (::X509_STORE_CTX_init(storeCtx, store, cert.Get(), chain.Get()) != 1) {
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

private:
    std::vector<Cert> intermediates_;
};

}
