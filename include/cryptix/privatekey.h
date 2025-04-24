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
    PrivateKey(PrivateKey&) = delete;
    PrivateKey& operator=(PrivateKey&) = delete;
    PrivateKey(PrivateKey&& key): key_(std::move(key.key_)) {}
    PrivateKey& operator=(PrivateKey&& key);

    std::optional<std::vector<uint8_t>> Sign(const std::vector<uint8_t>& data, SignAlgo algo);
    std::optional<std::vector<uint8_t>> Sign(const std::string& data, SignAlgo algo);

private:
    std::optional<std::vector<uint8_t>> Sign(const uint8_t* data, size_t size, SignAlgo algo);

private:
    UniqueEvpKey key_;
};

}
