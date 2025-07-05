#include "cryptix/privatekey.h"

#include <fstream>
#include <fmt/core.h>
#include <openssl/err.h>

#include "cryptix/error.h"

namespace Cryptix {

PrivateKey& PrivateKey::operator=(PrivateKey&& key) {
    if (this == &key) {
        return *this;
    }

    key_ = std::move(key.key_);
    key.key_ =nullptr;
    return *this;
}

std::optional<PrivateKey> PrivateKey::FromKeyFile(const std::filesystem::path& keyPath) {
    if (std::filesystem::exists(keyPath) == false) {
        CRYPTX_ERROR(fmt::format("{} not exists.", keyPath.string()));
        return std::nullopt;
    }

    std::ifstream ifs(keyPath);
    if (!ifs.is_open()) {
        CRYPTX_ERROR(fmt::format("{} open failed.", keyPath.string()));
        return std::nullopt;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return BaseKey::FromPrivateKeyContent(content);
}

std::optional<PrivateKey> PrivateKey::FromKeyContent(const std::string& keyContent) {
    auto key = BaseKey::FromPrivateKeyContent(keyContent);
    if (!key.has_value()) {
        return std::nullopt;
    }

    return PrivateKey(std::move(key.value()));
}

std::optional<std::vector<uint8_t>> PrivateKey::Sign(const std::vector<uint8_t>& data, SignAlgo algo) {
    if (data.size() == 0) {
        CRYPTX_ERROR("data empty.");
        return std::nullopt;
    }

    return Sign(data.data(), data.size(), algo);
}

std::optional<std::vector<uint8_t>> PrivateKey::Sign(const std::string& data, SignAlgo algo) {
    if (data.empty()) {
        CRYPTX_ERROR("data empty.");
        return std::nullopt;
    }

    return Sign(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), algo);
}

std::optional<std::vector<uint8_t>> PrivateKey::Sign(const uint8_t* data, size_t size, SignAlgo algo) {
    if (key_ == nullptr) {
        CRYPTX_ERROR("key nullptr");
        return std::nullopt;
    }

    UniqueEvpMdCtx mdCtx {::EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
    if (mdCtx == nullptr) {
        CRYPTX_ERROR("Allocate md ctx failed.");
        return std::nullopt;
    }

    ::EVP_PKEY_CTX* pkeyCtx;
    if (::EVP_DigestSignInit(mdCtx.get(), &pkeyCtx, EVP_sha256(), nullptr, key_.get()) <= 0) {
        CRYPTX_ERROR(fmt::format("Init sign failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return std::nullopt;
    }

    if (algo == SignAlgo::RSASSA_PSS) {
        if (::EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
            CRYPTX_ERROR(fmt::format("Set padding failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
            return std::nullopt;
        }
    } else if (algo == SignAlgo::ECC_ALGO) {
        // todo
    }
    // do nothing for RSA PKCS_V1.5 padding mode

    if (::EVP_DigestSignUpdate(mdCtx.get(), static_cast<const void*>(data), size) <= 0) {
        CRYPTX_ERROR(fmt::format("Update sign failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return std::nullopt;
    }

    size_t sigLen = 0;
    if (::EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) <= 0) {
        CRYPTX_ERROR(fmt::format("Finalize sign failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return std::nullopt;
    }

    std::vector<uint8_t> sig(sigLen);
    if (EVP_DigestSignFinal(mdCtx.get(), sig.data(), &sigLen) <= 0) {
        CRYPTX_ERROR(fmt::format("Update sign failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return std::nullopt;
    }

    sig.resize(sigLen);
    return sig;
}

}
