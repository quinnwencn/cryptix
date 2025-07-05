#include "cryptix/basekey.h"

#include <fmt/core.h>
#include <openssl/pem.h>

#include "cryptix/error.h"

namespace Cryptix {

std::optional<UniqueEvpKey> BaseKey::FromPublicKeyContent(const std::string& keyContent) {
    if (keyContent.empty()) {
        CRYPTX_ERROR("KeyContent empty");
        return std::nullopt;
    }

    UniqueBio bio {::BIO_new_mem_buf(keyContent.data(), keyContent.length()), BIO_free};
    if (bio == nullptr) {
        CRYPTX_ERROR("Allocate bio failed.");
        return std::nullopt;
    }

    UniqueEvpKey key {::PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    if (key == nullptr) {
        CRYPTX_ERROR("Allocate pub pkey failed.");
        return std::nullopt;
    }

    return key;
}

std::optional<UniqueEvpKey> BaseKey::FromPrivateKeyContent(const std::string& keyContent) {
    if (keyContent.empty()) {
        CRYPTX_ERROR("KeyContent empty");
        return std::nullopt;
    }

    UniqueBio bio {::BIO_new_mem_buf(keyContent.data(), keyContent.length()), BIO_free};
    if (bio == nullptr) {
        CRYPTX_ERROR("Allocate bio failed.");
        return std::nullopt;
    }

    UniqueEvpKey key {::PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    if (key == nullptr) {
        CRYPTX_ERROR("Allocate priv pkey failed.");
        return std::nullopt;
    }

    return key;
}

}
