#pragma once

#include <filesystem>
#include <string>
#include <optional>
#include <vector>

#include "_common.h"
#include "signalgorithm.h"
#include "basekey.h"

namespace Cryptix {

class PrivateKey : public BaseKey {
public:
    static std::optional<PrivateKey> FromKeyFile(const std::filesystem::path& keyPath);
    static std::optional<PrivateKey> FromKeyContent(const std::string& keyContent);
    
    PrivateKey(UniqueEvpKey&& key) : BaseKey(std::move(key)) {}
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    PrivateKey(PrivateKey&& key): BaseKey(std::move(key.key_)) {}
    PrivateKey& operator=(PrivateKey&& key);

    std::optional<std::vector<uint8_t>> Sign(const std::vector<uint8_t>& data, SignAlgo algo);
    std::optional<std::vector<uint8_t>> Sign(const std::string& data, SignAlgo algo);

private:
    std::optional<std::vector<uint8_t>> Sign(const uint8_t* data, size_t size, SignAlgo algo);
};

}
