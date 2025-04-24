#pragma once

#include <filesystem>
#include <string>
#include <optional>
#include <vector>

#include "_common.h"
#include "signalgorithm.h"

namespace Cryptix {

class PrivateKey {
public:
    static std::optional<PrivateKey> FromKeyFile(const std::filesystem::path& keyPath);
    static std::optional<PrivateKey> FromKeyContent(const std::string& keyContent);
    
    PrivateKey(UniqueEvpKey&& key) : key_(std::move(key)) {}

    std::optional<std::vector<uint8_t>> Sign(const std::vector<uint8_t>& data, SignAlgo algo);

private:
    UniqueEvpKey key_;
};

}
