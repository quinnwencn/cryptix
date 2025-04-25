#pragma once

#include <filesystem>
#include <string>
#include <optional>
#include <vector>

#include "_common.h"
#include "signalgorithm.h"
#include "basekey.h"

namespace Cryptix {

class PublicKey : public BaseKey {
public:
    static std::optional<PublicKey> FromKeyFile(const std::filesystem::path& keyFile);
    static std::optional<PublicKey> FromKeyContent(const std::string& keyContent);
    
    PublicKey(UniqueEvpKey&& key) : BaseKey(std::move(key)) {}

    bool Verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig, SignAlgo algo);
    bool Verify(const std::string& data, const std::vector<uint8_t>& sig, SignAlgo);

private:
    bool Verify(const uint8_t* data, size_t dataSize, const uint8_t* sig, size_t sigSize, SignAlgo);

};

}
