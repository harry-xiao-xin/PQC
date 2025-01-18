//
// Created by zpx on 2025/01/18.
//
#include "ml_kem/ml_kem_wrapper.hpp"
#include "test_helper.hpp"
#include <fstream>
#include <gtest/gtest.h>

TEST(ML_KEM_WRAPPER, ML_KEM_WRAPPER_512) {
   auto key_pair=ml_kem::ml_kem_512_keygen();
   std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher=
}