#include "cryptix/basekey.h"

#include <openssl/pem.h>

namespace Cryptix {

std::optional<UniqueEvpKey> FromPublicKeyContent(const std::string& keyContent) {
    if (keyContent.empty()) {
        return std::nullopt;
    }

    UniqueBio bio {::BIO_new_mem_buf(keyContent.data(), keyContent.length()), BIO_free};
    if (bio == nullptr) {
        return std::nullopt;
    }

    UniqueEvpKey key {::PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    if (key == nullptr) {
        return std::nullopt;
    }

    return key;
}

std::optional<UniqueEvpKey> FromPrivateKeyContent(const std::string& keyContent) {
    if (keyContent.empty()) {
        return std::nullopt;
    }

    UniqueBio bio {::BIO_new_mem_buf(keyContent.data(), keyContent.length()), BIO_free};
    if (bio == nullptr) {
        return std::nullopt;
    }

    UniqueEvpKey key {::PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    if (key == nullptr) {
        return std::nullopt;
    }

    return key;
}

}
