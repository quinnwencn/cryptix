#include "cryptix/publickey.h"

#include <fstream>
#include <fmt/core.h>
#include <openssl/pem.h>

#include "cryptix/error.h"

namespace Cryptix {

std::optional<PublicKey> PublicKey::FromKeyFile(const std::filesystem::path& keyFile) {
    if (std::filesystem::exists(keyFile) == false) {
        CRYPTX_ERROR(fmt::format("{} not exists.", keyFile.string()));
        return std::nullopt;
    }

    std::ifstream ifs(keyFile);
    if (!ifs.is_open()) {
        CRYPTX_ERROR(fmt::format("{} open failed.", keyFile.string()));
        return std::nullopt;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return BaseKey::FromPublicKeyContent(content);
}


std::optional<PublicKey> PublicKey::FromKeyContent(const std::string& keyContent) {
    auto key = BaseKey::FromPublicKeyContent(keyContent);
    if (!key.has_value()) {
        CRYPTX_ERROR("data empty.");
        return std::nullopt;
    }

    return PublicKey(std::move(key.value()));
}

bool PublicKey::Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig, SignAlgo algo) {
    if (data.empty() || sig.empty()) {
        CRYPTX_ERROR("data or sig empty.");
        return false;
    }

    return Verify(data.data(), data.size(), sig.data(), sig.size(), algo);
}

bool PublicKey::Verify(const std::string& data, const std::vector<uint8_t>& sig, SignAlgo algo) {
    if (data.empty() || sig.empty()) {
        CRYPTX_ERROR("data or sig empty.");
        return false;
    } 

    return Verify(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), sig.data(), sig.size(), algo);
}


bool PublicKey::Verify(const uint8_t* data, size_t dataSize, const uint8_t* sig, size_t sigSize, SignAlgo algo) {
    if (key_ == nullptr) {
        CRYPTX_ERROR("key nullptr");
        return false;
    }

    UniqueEvpMdCtx mdCtx {::EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
    if (mdCtx == nullptr) {
        CRYPTX_ERROR("Allocate md ctx failed.");
        return false;
    }

    ::EVP_PKEY_CTX* pkeyCtx;
    if (::EVP_DigestVerifyInit(mdCtx.get(), &pkeyCtx, EVP_sha256(), nullptr, key_.get()) <= 0) {
        CRYPTX_ERROR(fmt::format("Init verify failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return false;
    }

    if (algo == SignAlgo::RSASSA_PSS) {
        if (::EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
            CRYPTX_ERROR(fmt::format("Init sign failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
            return false;
        }
    } else if (algo == SignAlgo::ECC_ALGO) {
        // todo
    }
    // do nothing for RSA PKCS_V1.5 padding mode

    if (::EVP_DigestVerifyUpdate(mdCtx.get(), static_cast<const void*>(data), dataSize) <= 0) {
        CRYPTX_ERROR(fmt::format("Update verify failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return false;
    }

    if (::EVP_DigestVerifyFinal(mdCtx.get(), sig, sigSize) <= 0) {
        CRYPTX_ERROR(fmt::format("Finalize verify failed: {}", ::ERR_error_string(::ERR_get_error(), nullptr)));
        return false;
    }

    return true;
}

}
