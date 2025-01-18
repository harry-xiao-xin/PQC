//
// Created by zpx on 2025/01/18.
//

#ifndef PQC_ML_KEM_WRAPPER_H
#define PQC_ML_KEM_WRAPPER_H

#include <string>
#include "ml_kem/ml_kem_512.hpp"
#include "ml_kem/ml_kem_768.hpp"
#include "ml_kem/ml_kem_1024.hpp"
#include <vector>

namespace ml_kem {
    /**
     * generate ml_kem_512 public key and secret key
     * @return public key and secret key
     */
    auto ml_kem_512_keygen() {
        std::array<uint8_t, ml_kem_512::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_512::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<128> csprng{};
        csprng.generate(seed_d);
        csprng.generate(seed_z);
        ml_kem_512::keygen(seed_d, seed_z, pubkey, seckey);
        auto res = std::make_pair(pubkey, seckey);
        return res;
    }

    /**
     * generate ml_kem_512 shared secret text of cipher by public key
     * @param pubkey public key
     * @param cipher
     * @return shared secret text
     */
    auto ml_kem_512_encapsulate(std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> pubkey,
                             std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> shared_secret{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_512::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return shared_secret;
    }

    /**
     * recover ml_kem_512 cipher from shared secret text and secret key
     * @param seckey secret key
     * @param shared_secret shared secret text
     * @return cipher
     */
    auto ml_kem_512_decapsulate(
            std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> shared_secret) {
        std::array<uint8_t, ml_kem_512::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_512::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher{};
        randomshake::randomshake_t<128> csprng{};
        csprng.generate(seed_m);
        ml_kem_512::decapsulate(seckey, cipher, shared_secret);
        return cipher;
    }

    /**
     * generate ml_kem_768 public key and secret key
     * @return public key and secret key
     */
    auto ml_kem_768_keygen() {
        std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<192> csprng{};
        csprng.generate(seed_d);
        csprng.generate(seed_z);
        ml_kem_768::keygen(seed_d, seed_z, pubkey, seckey);
        auto res = std::make_pair(pubkey, seckey);
        return res;
    }

    /**
     * generate ml_kem_768 shared secret text of cipher by public key
     * @param pubkey public key
     * @param cipher
     * @return shared secret text
     */
    auto kem_768_encapsulate(std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pubkey,
                             std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_768::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return shared_secret;
    }

    /**
     * recover ml_kem_768 cipher from shared secret text and secret key
     * @param seckey secret key
     * @param shared_secret shared secret text
     * @return cipher
     */
    auto ml_kem_768_decapsulate(
            std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret) {
        std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher{};
        randomshake::randomshake_t<192> csprng{};
        csprng.generate(seed_m);
        ml_kem_768::decapsulate(seckey, cipher, shared_secret);
        return cipher;
    }

    /**
     * generate ml_kem_1024 public key and secret key
     * @return public key and secret key
     */
    auto ml_kem_1024_keygen() {
        std::array<uint8_t, ml_kem_1024::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_1024::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_1024::PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_1024::SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<256> csprng{};
        csprng.generate(seed_d);
        csprng.generate(seed_z);
        ml_kem_1024::keygen(seed_d, seed_z, pubkey, seckey);
        auto res = std::make_pair(pubkey, seckey);
        return res;
    }

    /**
     * generate ml_kem_1024 shared secret text of cipher by public key
     * @param pubkey public key
     * @param cipher
     * @return shared secret text
     */
    auto kem_1024_encapsulate(std::array<uint8_t, ml_kem_1024::PKEY_BYTE_LEN> pubkey,
                             std::array<uint8_t, ml_kem_1024::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_1024::SHARED_SECRET_BYTE_LEN> shared_secret{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_1024::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return shared_secret;
    }

    /**
     * recover ml_kem_1024 cipher from shared secret text and secret key
     * @param seckey secret key
     * @param shared_secret shared secret text
     * @return cipher
     */
    auto ml_kem_1024_decapsulate(
            std::array<uint8_t, ml_kem_1024::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_1024::SHARED_SECRET_BYTE_LEN> shared_secret) {
        std::array<uint8_t, ml_kem_1024::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_1024::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_1024::CIPHER_TEXT_BYTE_LEN> cipher{};
        randomshake::randomshake_t<256> csprng{};
        csprng.generate(seed_m);
        ml_kem_1024::decapsulate(seckey, cipher, shared_secret);
        return cipher;
    }
}
#endif //PQC_ML_KEM_WRAPPER_H
