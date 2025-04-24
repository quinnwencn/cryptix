#pragma once

#include <memory>
#include <openssl/x509.h>
#include <openssl/err.h>

namespace Cryptix {

enum class Result {
    SUCCESS = 0,
    FAILURE = 1,
    NOT_FOUND,
    INVALID,
    NOT_SUPPORTED,
    NO_MEMORY,
    NO_ENGINE,
    NO_SLOT,
    NO_KEY,
    NULLPTR,
};

using UniqueCert = std::unique_ptr<X509, decltype(&X509_free)>;
using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using UniqueEvpKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniqueEvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

}