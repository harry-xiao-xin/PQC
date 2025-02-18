//
// Created by zpx on 2025/02/12.
//
#include "com_example_pqc_MLKEMJNI.h"
#include "ml_kem/ml_kem_wrapper.hpp"
#include <iostream>
#include <jni.h>
#include <jni_md.h>
#include <utility>

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512CryptoKeygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_512_crypto_keygen();
     jbyte* pk_jnum = new jbyte[ml_kem_512::K_PKEY_BYTE_LEN];
     std::memcpy(pk_jnum, pk.begin(), ml_kem_512::K_PKEY_BYTE_LEN);
     env->SetByteArrayRegion(pk_jarray, 0, ml_kem_512::K_PKEY_BYTE_LEN, pk_jnum);
     jbyte* sk_jnum = new jbyte[ml_kem_512::K_SKEY_BYTE_LEN];
     std::memcpy(sk_jnum, sk.begin(), ml_kem_512::K_SKEY_BYTE_LEN);
     env->SetByteArrayRegion(sk_jarray, 0, ml_kem_512::K_SKEY_BYTE_LEN, sk_jnum);
     env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
     env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512Crypto(JNIEnv* env, jobject, jbyteArray pk, jbyteArray m)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_512::K_PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_512::K_PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  jbyte* m_bytes = env->GetByteArrayElements(m, 0);
  std::array<uint8_t, ml_kem_512::SEED_M_BYTE_LEN> m_{};
  memcpy(m_.data(), m_bytes, ml_kem_512::SEED_M_BYTE_LEN);
  env->ReleaseByteArrayElements(m, m_bytes, 0);
  auto cipher = ml_kem::ml_kem_512_crypto(pk_, m_);
  jbyteArray cipher_jarray = env->NewByteArray(ml_kem_512::K_CIPHER_TEXT_BYTE_LEN);
  jbyte* cipher_jnum = env->GetByteArrayElements(cipher_jarray, 0);
  std::memcpy(cipher_jnum, cipher.data(), ml_kem_512::K_CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher_jarray, 0, ml_kem_512::K_CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher_jarray, cipher_jnum, 0);
  return cipher_jarray;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512DeCrypto(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_512::K_SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_512::K_SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_512::K_CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_512::K_CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto m = ml_kem::ml_kem_512_decrypto(sk_, cipher_);
  jbyteArray m_jarray = env->NewByteArray(ml_kem_512::SEED_M_BYTE_LEN);
  jbyte* m_jnum = env->GetByteArrayElements(m_jarray, 0);
  std::memcpy(m_jnum, m.data(), ml_kem_512::SEED_M_BYTE_LEN);
  env->SetByteArrayRegion(m_jarray, 0, ml_kem_512::SEED_M_BYTE_LEN, m_jnum);
  env->ReleaseByteArrayElements(m_jarray, m_jnum, 0);
  return m_jarray;
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512Keygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_512_keygen();
  jbyte* pk_jnum = new jbyte[ml_kem_512::PKEY_BYTE_LEN];
  std::memcpy(pk_jnum, pk.data(), ml_kem_512::PKEY_BYTE_LEN);
  env->SetByteArrayRegion(pk_jarray, 0, ml_kem_512::PKEY_BYTE_LEN, pk_jnum);
  jbyte* sk_jnum = new jbyte[ml_kem_512::SKEY_BYTE_LEN];
  std::memcpy(sk_jnum, sk.data(), ml_kem_512::SKEY_BYTE_LEN);
  env->SetByteArrayRegion(sk_jarray, 0, ml_kem_512::SKEY_BYTE_LEN, sk_jnum);
  env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
  env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512Encapsulate(JNIEnv* env,
                                                  jobject,
                                                  jbyteArray pk,
                                                  jbyteArray cipher,
                                                  jbyteArray shared_key)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_512::PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_512::PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  auto [cipher_, shared_key_] = ml_kem::ml_kem_512_encapsulate(pk_);
  jbyte* cipher_jnum = new jbyte[ml_kem_512::K_CIPHER_TEXT_BYTE_LEN];
  std::memcpy(cipher_jnum, cipher_.data(), ml_kem_512::CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher, 0, ml_kem_512::CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher, cipher_jnum, 0);
  jbyte* shared_key_jnum = new jbyte[ml_kem_512::K_SKEY_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_512::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key, 0, ml_kem_512::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  env->ReleaseByteArrayElements(shared_key, shared_key_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem512Decapsulate(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_512::SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_512::SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_512::CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_512::CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto shared_key_ = ml_kem::ml_kem_512_decapsulate(sk_, cipher_);
  jbyteArray shared_key_jarray = env->NewByteArray(ml_kem_512::SHARED_SECRET_BYTE_LEN);
  jbyte* shared_key_jnum = new jbyte[ml_kem_512::SHARED_SECRET_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_512::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key_jarray, 0, ml_kem_512::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  return shared_key_jarray;
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768CryptoKeygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_768_crypto_keygen();
  jbyte* pk_jnum = new jbyte[ml_kem_768::K_PKEY_BYTE_LEN];
  std::memcpy(pk_jnum, pk.begin(), ml_kem_768::K_PKEY_BYTE_LEN);
  env->SetByteArrayRegion(pk_jarray, 0, ml_kem_768::K_PKEY_BYTE_LEN, pk_jnum);
  jbyte* sk_jnum = new jbyte[ml_kem_768::K_SKEY_BYTE_LEN];
  std::memcpy(sk_jnum, sk.begin(), ml_kem_768::K_SKEY_BYTE_LEN);
  env->SetByteArrayRegion(sk_jarray, 0, ml_kem_768::K_SKEY_BYTE_LEN, sk_jnum);
  env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
  env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768Crypto(JNIEnv* env, jobject, jbyteArray pk, jbyteArray m)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_768::K_PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_768::K_PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  jbyte* m_bytes = env->GetByteArrayElements(m, 0);
  std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m_{};
  memcpy(m_.data(), m_bytes, ml_kem_768::SEED_M_BYTE_LEN);
  env->ReleaseByteArrayElements(m, m_bytes, 0);
  auto cipher = ml_kem::ml_kem_768_crypto(pk_, m_);
  jbyteArray cipher_jarray = env->NewByteArray(ml_kem_768::K_CIPHER_TEXT_BYTE_LEN);
  jbyte* cipher_jnum = env->GetByteArrayElements(cipher_jarray, 0);
  std::memcpy(cipher_jnum, cipher.data(), ml_kem_768::K_CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher_jarray, 0, ml_kem_768::K_CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher_jarray, cipher_jnum, 0);
  return cipher_jarray;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768DeCrypto(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_768::K_SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_768::K_SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_768::K_CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_768::K_CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto m = ml_kem::ml_kem_768_decrypto(sk_, cipher_);
  jbyteArray m_jarray = env->NewByteArray(ml_kem_768::SEED_M_BYTE_LEN);
  jbyte* m_jnum = env->GetByteArrayElements(m_jarray, 0);
  std::memcpy(m_jnum, m.data(), ml_kem_768::SEED_M_BYTE_LEN);
  env->SetByteArrayRegion(m_jarray, 0, ml_kem_768::SEED_M_BYTE_LEN, m_jnum);
  env->ReleaseByteArrayElements(m_jarray, m_jnum, 0);
  return m_jarray;
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768Keygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_768_keygen();
  jbyte* pk_jnum = new jbyte[ml_kem_768::PKEY_BYTE_LEN];
  std::memcpy(pk_jnum, pk.data(), ml_kem_768::PKEY_BYTE_LEN);
  env->SetByteArrayRegion(pk_jarray, 0, ml_kem_768::PKEY_BYTE_LEN, pk_jnum);
  jbyte* sk_jnum = new jbyte[ml_kem_768::SKEY_BYTE_LEN];
  std::memcpy(sk_jnum, sk.data(), ml_kem_768::SKEY_BYTE_LEN);
  env->SetByteArrayRegion(sk_jarray, 0, ml_kem_768::SKEY_BYTE_LEN, sk_jnum);
  env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
  env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768Encapsulate(JNIEnv* env,
                                                  jobject,
                                                  jbyteArray pk,
                                                  jbyteArray cipher,
                                                  jbyteArray shared_key)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_768::PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  auto [cipher_, shared_key_] = ml_kem::ml_kem_768_encapsulate(pk_);
  jbyte* cipher_jnum = new jbyte[ml_kem_768::K_CIPHER_TEXT_BYTE_LEN];
  std::memcpy(cipher_jnum, cipher_.data(), ml_kem_768::CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher, 0, ml_kem_768::CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher, cipher_jnum, 0);
  jbyte* shared_key_jnum = new jbyte[ml_kem_768::K_SKEY_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_768::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key, 0, ml_kem_768::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  env->ReleaseByteArrayElements(shared_key, shared_key_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem768Decapsulate(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_768::SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_768::CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto shared_key_ = ml_kem::ml_kem_768_decapsulate(sk_, cipher_);
  jbyteArray shared_key_jarray = env->NewByteArray(ml_kem_768::SHARED_SECRET_BYTE_LEN);
  jbyte* shared_key_jnum = new jbyte[ml_kem_768::SHARED_SECRET_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_768::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key_jarray, 0, ml_kem_768::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  return shared_key_jarray;
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024CryptoKeygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_1024_crypto_keygen();
  jbyte* pk_jnum = new jbyte[ml_kem_1024::K_PKEY_BYTE_LEN];
  std::memcpy(pk_jnum, pk.begin(), ml_kem_1024::K_PKEY_BYTE_LEN);
  env->SetByteArrayRegion(pk_jarray, 0, ml_kem_1024::K_PKEY_BYTE_LEN, pk_jnum);
  jbyte* sk_jnum = new jbyte[ml_kem_1024::K_SKEY_BYTE_LEN];
  std::memcpy(sk_jnum, sk.begin(), ml_kem_1024::K_SKEY_BYTE_LEN);
  env->SetByteArrayRegion(sk_jarray, 0, ml_kem_1024::K_SKEY_BYTE_LEN, sk_jnum);
  env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
  env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024Crypto(JNIEnv* env, jobject, jbyteArray pk, jbyteArray m)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_1024::K_PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_1024::K_PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  jbyte* m_bytes = env->GetByteArrayElements(m, 0);
  std::array<uint8_t, ml_kem_1024::SEED_M_BYTE_LEN> m_{};
  memcpy(m_.data(), m_bytes, ml_kem_1024::SEED_M_BYTE_LEN);
  env->ReleaseByteArrayElements(m, m_bytes, 0);
  auto cipher = ml_kem::ml_kem_1024_crypto(pk_, m_);
  jbyteArray cipher_jarray = env->NewByteArray(ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN);
  jbyte* cipher_jnum = env->GetByteArrayElements(cipher_jarray, 0);
  std::memcpy(cipher_jnum, cipher.data(), ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher_jarray, 0, ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher_jarray, cipher_jnum, 0);
  return cipher_jarray;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024DeCrypto(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_1024::K_SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_1024::K_SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto m = ml_kem::ml_kem_1024_decrypto(sk_, cipher_);
  jbyteArray m_jarray = env->NewByteArray(ml_kem_1024::SEED_M_BYTE_LEN);
  jbyte* m_jnum = env->GetByteArrayElements(m_jarray, 0);
  std::memcpy(m_jnum, m.data(), ml_kem_1024::SEED_M_BYTE_LEN);
  env->SetByteArrayRegion(m_jarray, 0, ml_kem_1024::SEED_M_BYTE_LEN, m_jnum);
  env->ReleaseByteArrayElements(m_jarray, m_jnum, 0);
  return m_jarray;
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024Keygen(JNIEnv* env, jobject, jbyteArray pk_jarray, jbyteArray sk_jarray)
{
  auto [pk, sk] = ml_kem::ml_kem_1024_keygen();
  jbyte* pk_jnum = new jbyte[ml_kem_1024::PKEY_BYTE_LEN];
  std::memcpy(pk_jnum, pk.data(), ml_kem_1024::PKEY_BYTE_LEN);
  env->SetByteArrayRegion(pk_jarray, 0, ml_kem_1024::PKEY_BYTE_LEN, pk_jnum);
  jbyte* sk_jnum = new jbyte[ml_kem_1024::SKEY_BYTE_LEN];
  std::memcpy(sk_jnum, sk.data(), ml_kem_1024::SKEY_BYTE_LEN);
  env->SetByteArrayRegion(sk_jarray, 0, ml_kem_1024::SKEY_BYTE_LEN, sk_jnum);
  env->ReleaseByteArrayElements(pk_jarray, pk_jnum, 0);
  env->ReleaseByteArrayElements(sk_jarray, sk_jnum, 0);
}

JNIEXPORT void JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024Encapsulate(JNIEnv* env,
                                                   jobject,
                                                   jbyteArray pk,
                                                   jbyteArray cipher,
                                                   jbyteArray shared_key)
{
  jbyte* pk_bytes = env->GetByteArrayElements(pk, 0);
  std::array<uint8_t, ml_kem_1024::PKEY_BYTE_LEN> pk_{};
  memcpy(pk_.data(), pk_bytes, ml_kem_1024::PKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(pk, pk_bytes, 0);
  auto [cipher_, shared_key_] = ml_kem::ml_kem_1024_encapsulate(pk_);
  jbyte* cipher_jnum = new jbyte[ml_kem_1024::K_CIPHER_TEXT_BYTE_LEN];
  std::memcpy(cipher_jnum, cipher_.data(), ml_kem_1024::CIPHER_TEXT_BYTE_LEN);
  env->SetByteArrayRegion(cipher, 0, ml_kem_1024::CIPHER_TEXT_BYTE_LEN, cipher_jnum);
  env->ReleaseByteArrayElements(cipher, cipher_jnum, 0);
  jbyte* shared_key_jnum = new jbyte[ml_kem_1024::K_SKEY_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_1024::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key, 0, ml_kem_1024::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  env->ReleaseByteArrayElements(shared_key, shared_key_jnum, 0);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pqc_MLKEMJNI_mlkem1024Decapsulate(JNIEnv* env, jobject, jbyteArray sk, jbyteArray cipher)
{
  jbyte* sk_bytes = env->GetByteArrayElements(sk, 0);
  std::array<uint8_t, ml_kem_1024::SKEY_BYTE_LEN> sk_{};
  memcpy(sk_.data(), sk_bytes, ml_kem_1024::SKEY_BYTE_LEN);
  env->ReleaseByteArrayElements(sk, sk_bytes, 0);
  jbyte* cipher_bytes = env->GetByteArrayElements(cipher, 0);
  std::array<uint8_t, ml_kem_1024::CIPHER_TEXT_BYTE_LEN> cipher_{};
  memcpy(cipher_.data(), cipher_bytes, ml_kem_1024::CIPHER_TEXT_BYTE_LEN);
  env->ReleaseByteArrayElements(cipher, cipher_bytes, 0);
  auto shared_key_ = ml_kem::ml_kem_1024_decapsulate(sk_, cipher_);
  jbyteArray shared_key_jarray = env->NewByteArray(ml_kem_1024::SHARED_SECRET_BYTE_LEN);
  jbyte* shared_key_jnum = new jbyte[ml_kem_1024::SHARED_SECRET_BYTE_LEN];
  std::memcpy(shared_key_jnum, shared_key_.data(), ml_kem_1024::SHARED_SECRET_BYTE_LEN);
  env->SetByteArrayRegion(shared_key_jarray, 0, ml_kem_1024::SHARED_SECRET_BYTE_LEN, shared_key_jnum);
  return shared_key_jarray;
}
