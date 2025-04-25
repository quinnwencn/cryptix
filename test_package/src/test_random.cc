#include "cryptix/random.h"
#include "cryptix/utils.h"

#include <gtest/gtest.h>
#include <unordered_set>
#include <

using namespace Cryptix;

TEST(RandomGenTest, ValidSizeRandomGenTest) {
    const size_t TEST_SIZES[] {1, 16, 32, 128};
    for (auto size : TEST_SIZES) {
        auto ret = RandomGen::RandomNum(size);
        EXPECT_TRUE(ret.has_value());
        EXPECT_EQ(ret.value().size(), size);
    }
}

TEST(RandomGenTest, RandomnessTest) {
    size_t testSize {32};
    int runTimes {100};
    std::unordered_set<std::string> uniqueStr;

    for (auto i = 0; i < runTimes; ++i) {
        auto res = RandomGen::RandomNum(testSize);
        EXPECT_TRUE(res.has_value());

        auto vec = res.value();
        int zeroCount = std::count(vec.begin(), vec.end(), 0);
        int maxCount = std::count(vec.begin(), vec.end(), UINT8_MAX);
        EXPECT_TRUE(zeroCount < testSize / 2);
        EXPECT_TRUE(maxCount < testSize / 2);

        auto insertIter = uniqueStr.insert(Utils::ByteArr2HexStr(vec));
        EXPECT_TRUE(insertIter.second);
    }
}
