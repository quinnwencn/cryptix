#pragma once

#include <optional>
#include <vector>
#include <cstdint>

namespace Cryptix {

class RandomGen {
public:
    RandomGen() = default;
    ~RandomGen() = default;

    static std::optional<std::vector<uint8_t>> RandomNum(size_t size);

};

}
