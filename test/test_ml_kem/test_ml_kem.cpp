//
// Created by zpx on 2025/01/18.
//
#include "ml_kem/ml_kem_wrapper.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include "../test_utils/test_helper.hpp"

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_512) {
    auto [public_key, private_key] = ml_kem::ml_kem_512_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_512_encapsulate(public_key);
    auto re_shared_key = ml_kem::ml_kem_512_decapsulate(private_key, cipher);
    ASSERT_EQ(shared_key, re_shared_key);
}

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_512_CRYPTO) {
    auto [public_key, private_key] = ml_kem::ml_kem_512_crypto_keygen();
    std::array<uint8_t, 32> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_512_crypto(public_key, m1);
    auto m2 = ml_kem::ml_kem_512_decrypto(private_key, cipher);
    ASSERT_EQ(m1, m2);
}

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_768) {
    auto [public_key, private_key] = ml_kem::ml_kem_768_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_768_encapsulate(public_key);
    auto re_shared_key = ml_kem::ml_kem_768_decapsulate(private_key, cipher);
    ASSERT_EQ(shared_key, re_shared_key);
}

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_768_CRYPTO) {
    auto [public_key, private_key] = ml_kem::ml_kem_768_crypto_keygen();
    std::array<uint8_t, 32> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_768_crypto(public_key, m1);
    auto m2 = ml_kem::ml_kem_768_decrypto(private_key, cipher);
    ASSERT_EQ(m1, m2);
}

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_1024) {
    auto [public_key, private_key] = ml_kem::ml_kem_1024_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_1024_encapsulate(public_key);
    auto re_shared_key = ml_kem::ml_kem_1024_decapsulate(private_key, cipher);
    ASSERT_EQ(shared_key, re_shared_key);
}

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_1024_CRYPTO) {
    auto [public_key, private_key] = ml_kem::ml_kem_1024_crypto_keygen();
    std::array<uint8_t, 32> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_1024_crypto(public_key, m1);
    auto m2 = ml_kem::ml_kem_1024_decrypto(private_key, cipher);
    ASSERT_EQ(m1, m2);
}