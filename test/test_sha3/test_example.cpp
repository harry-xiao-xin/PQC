//
// Created by zpx on 2025/01/14.
//
#include "sha3/sha3_224.hpp"
#include "test_utils.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <vector>
#include "test_example.hpp"

TEST(test_sha3_224_test, test_sha3_224) {
    constexpr size_t ilen = 32;
    constexpr size_t olen = sha3_224::DIGEST_LEN;
    std::vector<uint8_t> msg(ilen, 0);
    std::vector<uint8_t> dig(olen, 0);
    auto _dig = std::span<uint8_t, olen>(dig);
    random_data < uint8_t > (msg);
    sha3_224::sha3_224_t hasher;
    hasher.absorb(msg);
    hasher.finalize();
    hasher.digest(_dig);
    std::cout << "SHA3-224" << std::endl << std::endl;
    std::cout << "Input  : " << to_hex(msg) << "\n";
    std::cout << "Output : " << to_hex(dig) << "\n";
}