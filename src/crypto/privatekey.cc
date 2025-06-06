#include "cryptix/privatekey.h"

#include <fstream>

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
        return std::nullopt;
    }

    std::ifstream ifs(keyPath);
    if (!ifs.is_open()) {
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
        return std::nullopt;
    }

    return Sign(data.data(), data.size(), algo);
}

std::optional<std::vector<uint8_t>> PrivateKey::Sign(const std::string& data, SignAlgo algo) {
    if (data.empty()) {
        return std::nullopt;
    }

    return Sign(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), algo);
}

std::optional<std::vector<uint8_t>> PrivateKey::Sign(const uint8_t* data, size_t size, SignAlgo algo) {
    if (key_ == nullptr) {
        return std::nullopt;
    }

    UniqueEvpMdCtx mdCtx {::EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
    if (mdCtx == nullptr) {
        return std::nullopt;
    }

    ::EVP_PKEY_CTX* pkeyCtx;
    if (::EVP_DigestSignInit(mdCtx.get(), &pkeyCtx, EVP_sha256(), nullptr, key_.get()) <= 0) {
        return std::nullopt;
    }

    if (algo == SignAlgo::RSASSA_PSS) {
        if (::EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
            return std::nullopt;
        }
    } else if (algo == SignAlgo::ECC_ALGO) {
        // todo
    }
    // do nothing for RSA PKCS_V1.5 padding mode

    if (::EVP_DigestSignUpdate(mdCtx.get(), static_cast<const void*>(data), size) <= 0) {
        return std::nullopt;
    }

    size_t sigLen = 0;
    if (::EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) <= 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> sig(sigLen);
    if (EVP_DigestSignFinal(mdCtx.get(), sig.data(), &sigLen) <= 0) {
        return std::nullopt;
    }

    sig.resize(sigLen);
    return sig;
}

}
