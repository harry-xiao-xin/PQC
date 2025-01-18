#include "ml_kem/internals/math/field.hpp"
#include "random_shake/randomshake.hpp"
#include <gtest/gtest.h>

// Test functional correctness of ML-KEM prime field operations, by running through multiple rounds
// of execution of field operations on randomly sampled field elements.
TEST(ML_KEM, ArithmeticOverZq)
{
  constexpr size_t ITERATION_COUNT = 1ul << 20;

  randomshake::randomshake_t<128> csprng{};

  for (size_t i = 0; i < ITERATION_COUNT; i++) {
    const auto a = ml_kem_field::zq_t::random(csprng);
    const auto b = ml_kem_field::zq_t::random(csprng);

    // Addition, Subtraction and Negation
    const auto c = a + b;
    const auto d = c - b;
    const auto e = c - a;

    EXPECT_EQ(d.raw(), a.raw());
    EXPECT_EQ(e.raw(), b.raw());

    // Multiplication, Exponentiation, Inversion and Division
    const auto f = a * b;
    const auto g = f / b;
    const auto h = f / a;

    if (b != ml_kem_field::zq_t::zero()) {
        EXPECT_EQ(g.raw(), a.raw());
    } else {
      EXPECT_EQ(g.raw(), ml_kem_field::zq_t::zero().raw());
    }

    if (a != ml_kem_field::zq_t::zero()) {
      EXPECT_EQ(h.raw(), b.raw());
    } else {
      EXPECT_EQ(h.raw(), ml_kem_field::zq_t::zero().raw());
    }
  }
}
