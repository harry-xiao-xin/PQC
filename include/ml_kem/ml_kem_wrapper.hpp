//
// Created by zpx on 2025/01/18.
//

#pragma once

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
        return std::make_pair(pubkey, seckey);
    }

    /**
     * generate ml_kem_512 crypto public key and secret key
     * @return  public key and secret key
     */
    auto ml_kem_512_crypto_keygen() {
        std::array<uint8_t, ml_kem_512::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_512::K_PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_512::K_SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<128> csprng{};
        csprng.generate(seed_d);
        ml_kem_512::crypto_keygen(seed_d, pubkey, seckey);
        return std::make_pair(pubkey, seckey);
    }

    /**
     * ml_kem_512 crypto message by public key
     * @param pubkey  public key
     * @param m message
     * @return cipher
     */
    auto ml_kem_512_crypto(std::array<uint8_t, ml_kem_512::K_PKEY_BYTE_LEN> pubkey,
                           std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m) {
        std::array<uint8_t, ml_kem_512::K_CIPHER_TEXT_BYTE_LEN> cipher{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_512::crypto(m, pubkey, cipher);
        assert(is_encapsulated);
        return cipher;
    }

    /**
     * ml_kem_512 decrypto message by secret key and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return message
     */
    auto ml_kem_512_decrypto(
            std::array<uint8_t, ml_kem_512::K_SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_512::K_CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m{};
        ml_kem_512::decrypto(seckey, cipher, m);
        return m;
    }

    /**
     * generate cipher and shared secret text from public key
     * @param pubkey public key
     * @return cipher and shared secret
     */
    auto ml_kem_512_encapsulate(std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> pubkey) {
        std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher{};
        std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> shared_secret{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_512::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return std::make_pair(cipher, shared_secret);
    }

    /**
     * recover shared_secret from secret key and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return shared_secret
     */
    auto ml_kem_512_decapsulate(
            std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_512::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_512::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_512::SHARED_SECRET_BYTE_LEN> shared_secret{};
        randomshake::randomshake_t<128> csprng{};
        csprng.generate(seed_m);
        ml_kem_512::decapsulate(seckey, cipher, shared_secret);
        return shared_secret;
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
        return std::make_pair(pubkey, seckey);
    }

    /**
        * generate ml_kem_768 crypto public key and secret key
        * @return  public key and secret key
        */
    auto ml_kem_768_crypto_keygen() {
        std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_768::K_PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_768::K_SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<192> csprng{};
        csprng.generate(seed_d);
        ml_kem_768::crypto_keygen(seed_d, pubkey, seckey);
        return std::make_pair(pubkey, seckey);
    }

    /**
     * ml_kem_768 crypto message by public key
     * @param pubkey  public key
     * @param m message
     * @return cipher
     */
    auto ml_kem_768_crypto(std::array<uint8_t, ml_kem_768::K_PKEY_BYTE_LEN> pubkey,
                           std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m) {
        std::array<uint8_t, ml_kem_768::K_CIPHER_TEXT_BYTE_LEN> cipher{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_768::crypto(m, pubkey, cipher);
        assert(is_encapsulated);
        return cipher;
    }

    /**
     * ml_kem_512 decrypto message by secret key and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return message
     */
    auto ml_kem_768_decrypto(
            std::array<uint8_t, ml_kem_768::K_SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_768::K_CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m{};
        ml_kem_768::decrypto(seckey, cipher, m);
        return m;
    }

    /**
     * generate ml_kem_768 cipher and shared secret text from public key
     * @param pubkey public key
     * @return cipher and shared secret text
     */
    auto ml_kem_768_encapsulate(std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pubkey) {
        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret{};
        std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_768::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return std::make_pair(cipher, shared_secret);
    }

    /**
     * recover ml_kem_768 shared secret text from  secret key and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return shared_secret
     */
    auto ml_kem_768_decapsulate(
            std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret{};
        randomshake::randomshake_t<192> csprng{};
        csprng.generate(seed_m);
        ml_kem_768::decapsulate(seckey, cipher, shared_secret);
        return shared_secret;
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
        return std::make_pair(pubkey, seckey);
    }

    /**
        * generate ml_kem_1024 crypto public key and secret key
        * @return  public key and secret key
        */
    auto ml_kem_1024_crypto_keygen() {
        std::array<uint8_t, ml_kem_1024::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_1024::K_PKEY_BYTE_LEN> pubkey{};
        std::array<uint8_t, ml_kem_1024::K_SKEY_BYTE_LEN> seckey{};
        randomshake::randomshake_t<256> csprng{};
        csprng.generate(seed_d);
        ml_kem_1024::crypto_keygen(seed_d, pubkey, seckey);
        return std::make_pair(pubkey, seckey);
    }

    /**
     * ml_kem_1024 crypto message by public key
     * @param pubkey  public key
     * @param m message
     * @return cipher
     */
    auto ml_kem_1024_crypto(std::array<uint8_t, ml_kem_1024::K_PKEY_BYTE_LEN> pubkey,
                            std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> m) {
        std::array<uint8_t, ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN> cipher{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_1024::crypto(m, pubkey, cipher);
        assert(is_encapsulated);
        return cipher;
    }

    /**
     * ml_kem_1024 decrypto message by secret key and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return message
     */
    auto ml_kem_1024_decrypto(
            std::array<uint8_t, ml_kem_1024::K_SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> m{};
        ml_kem_1024::decrypto(seckey, cipher, m);
        return m;
    }

    /**
     * generate ml_kem_1024 cipher and shared secret text from public key
     * @param pubkey public key
     * @return cipher and shared secret text
     */
    auto ml_kem_1024_encapsulate(std::array<uint8_t, ml_kem_1024::PKEY_BYTE_LEN> pubkey) {
        std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_1024::CIPHER_TEXT_BYTE_LEN> cipher{};
        std::array<uint8_t, ml_kem_1024::SHARED_SECRET_BYTE_LEN> shared_secret{};
        bool is_encapsulated = true;
        is_encapsulated &= ml_kem_1024::encapsulate(seed_m, pubkey, cipher, shared_secret);
        assert(is_encapsulated);
        return std::make_pair(cipher, shared_secret);
    }

    /**
     * recover ml_kem_1024 share secret text from secret keky and cipher
     * @param seckey secret key
     * @param cipher cipher
     * @return shared secret text
     */
    auto ml_kem_1024_decapsulate(
            std::array<uint8_t, ml_kem_1024::SKEY_BYTE_LEN> seckey,
            std::array<uint8_t, ml_kem_1024::CIPHER_TEXT_BYTE_LEN> cipher) {
        std::array<uint8_t, ml_kem_1024::SEED_D_BYTE_LEN> seed_d{};
        std::array<uint8_t, ml_kem_1024::SEED_Z_BYTE_LEN> seed_z{};
        std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> seed_m{};
        std::array<uint8_t, ml_kem_1024::SHARED_SECRET_BYTE_LEN> shared_secret{};
        randomshake::randomshake_t<256> csprng{};
        csprng.generate(seed_m);
        ml_kem_1024::decapsulate(seckey, cipher, shared_secret);
        return shared_secret;
    }
}
