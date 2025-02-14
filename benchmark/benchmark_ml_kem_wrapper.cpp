//
// Created by zpx on 2025/01/20.
//
#include "ml_kem/ml_kem_wrapper.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

void bench_ml_kem_512_wrap_gen(benchmark::State &state) {
    for (auto _: state) {
        auto [public_key, private_key] = ml_kem::ml_kem_512_keygen();
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_512_wrap_encapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_512_keygen();
    for (auto _: state) {
        auto [cipher, shared_key] = ml_kem::ml_kem_512_encapsulate(public_key);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_512_wrap_decapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_512_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_512_encapsulate(public_key);
    for (auto _: state) {
        auto re_shared_key = ml_kem::ml_kem_512_decapsulate(private_key, cipher);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::DoNotOptimize(re_shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_wrap_gen(benchmark::State &state) {
    for (auto _: state) {
        auto [public_key, private_key] = ml_kem::ml_kem_768_keygen();
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_wrap_encapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_768_keygen();
    for (auto _: state) {
        auto [cipher, shared_key] = ml_kem::ml_kem_768_encapsulate(public_key);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_wrap_decapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_768_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_768_encapsulate(public_key);
    for (auto _: state) {
        auto re_shared_key = ml_kem::ml_kem_768_decapsulate(private_key, cipher);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::DoNotOptimize(re_shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_wrap_gen(benchmark::State &state) {
    for (auto _: state) {
        auto [public_key, private_key] = ml_kem::ml_kem_1024_keygen();
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_wrap_encapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_1024_keygen();
    for (auto _: state) {
        auto [cipher, shared_key] = ml_kem::ml_kem_1024_encapsulate(public_key);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_wrap_decapsulate(benchmark::State &state) {
    auto [public_key, private_key] = ml_kem::ml_kem_1024_keygen();
    auto [cipher, shared_key] = ml_kem::ml_kem_1024_encapsulate(public_key);
    for (auto _: state) {
        auto re_shared_key = ml_kem::ml_kem_1024_decapsulate(private_key, cipher);
        benchmark::DoNotOptimize(public_key);
        benchmark::DoNotOptimize(private_key);
        benchmark::DoNotOptimize(cipher);
        benchmark::DoNotOptimize(shared_key);
        benchmark::DoNotOptimize(re_shared_key);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_512_crypto_keygen(benchmark::State &state) {
    for (auto _: state) {
        auto [pk, sk] = ml_kem::ml_kem_512_crypto_keygen();
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_512_crypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_512_crypto_keygen();
    std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m);
    for (auto _: state) {
        auto cipher = ml_kem::ml_kem_512_crypto(pk, m);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_512_decrypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_512_crypto_keygen();
    std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_512_crypto(pk, m1);
    for (auto _: state) {
        auto m2 = ml_kem::ml_kem_512_decrypto(sk, cipher);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m1);
        benchmark::DoNotOptimize(m2);
        benchmark::DoNotOptimize(cipher);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_crypto_keygen(benchmark::State &state) {
    for (auto _: state) {
        auto [pk, sk] = ml_kem::ml_kem_768_crypto_keygen();
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_crypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_768_crypto_keygen();
    std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m);
    for (auto _: state) {
        auto cipher = ml_kem::ml_kem_768_crypto(pk, m);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_768_decrypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_768_crypto_keygen();
    std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_768_crypto(pk, m1);
    for (auto _: state) {
        auto m2 = ml_kem::ml_kem_768_decrypto(sk, cipher);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m1);
        benchmark::DoNotOptimize(m2);
        benchmark::DoNotOptimize(cipher);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_crypto_keygen(benchmark::State &state) {
    for (auto _: state) {
        auto [pk, sk] = ml_kem::ml_kem_1024_crypto_keygen();
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_crypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_1024_crypto_keygen();
    std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> m{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m);
    for (auto _: state) {
        auto cipher = ml_kem::ml_kem_1024_crypto(pk, m);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

void bench_ml_kem_1024_decrypto(benchmark::State &state) {
    auto [pk, sk] = ml_kem::ml_kem_1024_crypto_keygen();
    std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> m1{};
    randomshake::randomshake_t<128> csprng{};
    csprng.generate(m1);
    auto cipher = ml_kem::ml_kem_1024_crypto(pk, m1);
    for (auto _: state) {
        auto m2 = ml_kem::ml_kem_1024_decrypto(sk, cipher);
        benchmark::DoNotOptimize(pk);
        benchmark::DoNotOptimize(sk);
        benchmark::DoNotOptimize(m1);
        benchmark::DoNotOptimize(m2);
        benchmark::DoNotOptimize(cipher);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(bench_ml_kem_512_wrap_gen)->Unit(benchmark::kMillisecond)->Name("ml_kem_512_wrap/gen")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_512_wrap_encapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_512_wrap/encapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_512_wrap_decapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_512_wrap/decapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_wrap_gen)->Unit(benchmark::kMillisecond)->Name("ml_kem_768_wrap/gen")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_wrap_encapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_768_wrap/encapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_wrap_decapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_768_wrap/decapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_wrap_gen)->Unit(benchmark::kMillisecond)->Name("ml_kem_1024_wrap/gen")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_wrap_encapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_1024_wrap/encapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_wrap_decapsulate)->Unit(benchmark::kMillisecond)->Name("ml_kem_1024_wrap/decapsulate")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_512_crypto_keygen)->Unit(benchmark::kMillisecond)->Name("ml_kem_512/crypto_keygen")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_512_crypto)->Unit(benchmark::kMillisecond)->Name("ml_kem_512/crypto")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_512_decrypto)->Unit(benchmark::kMillisecond)->Name("ml_kem_512/decrypto")
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_crypto_keygen)->Name("ml_kem_768/crypto_keygen")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_crypto)->Name("ml_kem_768/crypto")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_768_decrypto)->Name("ml_kem_768/decrypto")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_crypto_keygen)->Name("ml_kem_1024/crypto_keygen")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_crypto)->Name("ml_kem_1024/crypto")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_ml_kem_1024_decrypto)->Name("ml_kem_1024/decrypto")->Unit(benchmark::kMillisecond)
        ->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);