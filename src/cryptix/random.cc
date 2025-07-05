#include "cryptix/random.h"

#include <random>

#include "cryptix/error.h"

namespace Cryptix {

std::optional<std::vector<uint8_t>> RandomGen::RandomNum(size_t size) {
    // in linux
    std::random_device rd {"/dev/random"};
    if (rd.entropy() == 0) {
        CRYPTX_ERROR("entropy not ready.");
        return std::nullopt;
    }

    if (size == 0) {
        CRYPTX_ERROR("random size invalid");
        return std::nullopt;
    }

    std::vector<uint8_t> buff(size);
    for (auto& byte : buff) {
        byte = rd();
    }

    return buff;
}

}