#pragma once

#include<stdlib.h>
#include "config.hpp"
#include "symmetric.hpp"


namespace ml_dsa {
    constexpr size_t SEEDBYTES = 32;
    constexpr size_t CRHBYTES = 64;
    static constexpr size_t TRBYTES = 64;
    static constexpr size_t RNDBYTES = 32;
    static constexpr size_t N = 256;
    static constexpr size_t Q = 8380417;
    static constexpr size_t D = 13;
    static constexpr size_t ROOT_OF_UNITY = 1753;
#if DILITHIUM_MODE == 2
    static constexpr size_t K = 4;
    static constexpr size_t L = 4;
    static constexpr size_t ETA = 2;
    static constexpr size_t TAU = 39;
    static constexpr size_t BETA = 78;
    static constexpr size_t GAMMA1 = (1 << 17);
    static constexpr size_t GAMMA2 = ((Q - 1) / 88);
    static constexpr size_t OMEGA = 80;
    static constexpr size_t CTILDEBYTES = 32;
    static constexpr size_t POLYZ_PACKEDBYTES = 576;
    static constexpr size_t POLYW1_PACKEDBYTES = 192;
    static constexpr size_t POLYETA_PACKEDBYTES = 96;
    static constexpr size_t POLY_UNIFORM_ETA_NBLOCKS = ((136 + 136 - 1) / 136);
#elif DILITHIUM_MODE == 3
    size_t K = 6;
    size_t L = 5;
    size_t ETA = 4;
    size_t TAU = 49;
    size_t BETA = 196;
    size_t GAMMA1 = (1 << 19);
    size_t GAMMA2 = ((Q - 1) / 32);
    size_t OMEGA = 55;
    size_t CTILDEBYTES = 48;
    size_t POLYZ_PACKEDBYTES = 640;
    size_t POLYW1_PACKEDBYTES = 128;
    size_t POLYETA_PACKEDBYTES = 128;
    static constexpr  POLY_UNIFORM_ETA_NBLOCKS= ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES);
#elif DILITHIUM_MODE == 5
    size_t K = 8;
    size_t L = 7;
    size_t ETA = 2;
    size_t TAU = 60;
    size_t BETA = 120;
    size_t GAMMA1 = (1 << 19);
    size_t GAMMA2 = ((Q - 1) / 32);
    size_t OMEGA = 75;
    size_t CTILDEBYTES = 64;
    size_t POLYZ_PACKEDBYTES = 640;
    size_t POLYW1_PACKEDBYTES = 128;
    size_t POLYETA_PACKEDBYTES = 96;
       static constexpr size_t POLY_UNIFORM_ETA_NBLOCKS = ((136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES);
#endif
    static constexpr size_t POLYT1_PACKEDBYTES = 320;
    static constexpr size_t POLYT0_PACKEDBYTES = 416;
    static constexpr size_t POLYVECH_PACKEDBYTES = (OMEGA + K);
    static constexpr size_t CRYPTO_PUBLICKEYBYTES = (SEEDBYTES + K * POLYT1_PACKEDBYTES);
    static constexpr size_t CRYPTO_SECRETKEYBYTES = (2 * SEEDBYTES
                                                     + TRBYTES
                                                     + L * POLYETA_PACKEDBYTES
                                                     + K * POLYETA_PACKEDBYTES
                                                     + K * POLYT0_PACKEDBYTES);
    static constexpr size_t CRYPTO_BYTES = (CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES);
}
