#pragma once

#include <string>
#include <filesystem>
#include <string_view>
#include <optional>
#include <memory>

#include "_common.h"

namespace Cryptix {

class Cert {
public:
    static std::optional<Cert> FromPemText(std::string_view pemText);
    static std::optional<Cert> FromPemFile(std::filesystem::path pemFile);
    static std::optional<Cert> FromDerText(std::string_view derText);
    static std::optional<Cert> FromDerFile(std::filesystem::path derFile);

    Result ToPemFile(std::filesystem::path pemFile) const;
    Result ToDerFile(std::filesystem::path derFile) const;
    Result ToPemText(std::string& pemText) const;
    Result ToDerText(std::string& derText) const;

    bool IsCA() const { return ::X509_check_ca(cert_.get()) == 1; }
    X509* Get() { return cert_.get(); }
    UniqueEvpKey PublicKey() const {
        return UniqueEvpKey(X509_get_pubkey(cert_.get()), EVP_PKEY_free);
    }

private:
    std::shared_ptr<X509> cert_;

    Cert() : cert_(nullptr) {};
};

} // namespace Cryptix
