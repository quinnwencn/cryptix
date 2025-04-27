#pragma once

#include "cert.h"

namespace Cryptix {

class ICertValidator {
public:
    virtual ~ICertValidator() = default;
    virtual bool Verify(X509_STORE* store, Cert& cert) = 0;
};

}