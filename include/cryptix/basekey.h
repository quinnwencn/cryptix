#pragma once

#include <filesystem>
#include <string>
#include <optional>
#include <vector>

#include "_common.h"

namespace Cryptix {

class BaseKey {
public:
    static std::optional<UniqueEvpKey> FromPublicKeyContent(const std::string& keyContent);
    static std::optional<UniqueEvpKey> FromPrivateKeyContent(const std::string& keyContent);
    
    BaseKey(UniqueEvpKey&& key) : key_(std::move(key)) {}

protected:
    UniqueEvpKey key_;
};

}
