#include <iostream>
#include"ml_kem/ml_kem_wrapper.hpp"
#include "test/test_utils/test_helper.hpp"

int main() {
    auto [public_key, private_key] = ml_kem::ml_kem_1024_crypto_keygen();
    std::array<uint8_t, 32> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_1024_crypto(public_key, m1);
    auto m2 = ml_kem::ml_kem_1024_decrypto(private_key, cipher);
    std::cout << to_hex(m1) << std::endl;
    std::cout << to_hex(m2) << std::endl;
//    ASSERT_EQ(m1, m2);
}
