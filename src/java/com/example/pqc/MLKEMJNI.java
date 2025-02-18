package com.example.pqc;

import java.nio.file.FileSystems;
import java.util.Arrays;

import javafx.util.Pair;

public class MLKEMJNI {
    // ML-KEM-512
    public static Integer MLKEM_512_CRYPTO_PK_LEN = 800;
    public static Integer MLKEM_512_CRYPTO_SK_LEN = 768;
    public static Integer MLKEM_512_CRYPTO_M_LEN = 32;
    public static Integer MLKEM_512_CRYPTO_CIPHER_LEN = 768;

    public static Integer MLKEM_512_PK_LEN = 800;
    public static Integer MLKEM_512_SK_LEN = 1632;
    public static Integer MLKEM_512_M_LEN = 32;
    public static Integer MLKEM_512_CIPHER_LEN = 768;
    public static Integer MLKEM_512_SHARED_KEY_LEN = 32;

    // ML-KEM-768
    public static Integer MLKEM_768_CRYPTO_PK_LEN = 1184;
    public static Integer MLKEM_768_CRYPTO_SK_LEN = 1152;
    public static Integer MLKEM_768_CRYPTO_M_LEN = 32;
    public static Integer MLKEM_768_CRYPTO_CIPHER_LEN = 1088;

    public static Integer MLKEM_768_PK_LEN = 1184;
    public static Integer MLKEM_768_SK_LEN = 2400;
    public static Integer MLKEM_768_M_LEN = 32;
    public static Integer MLKEM_768_CIPHER_LEN = 1088;
    public static Integer MLKEM_768_SHARED_KEY_LEN = 32;

    // ML-KEM-1024
    public static Integer MLKEM_1024_CRYPTO_PK_LEN = 1568;
    public static Integer MLKEM_1024_CRYPTO_SK_LEN = 1536;
    public static Integer MLKEM_1024_CRYPTO_M_LEN = 32;
    public static Integer MLKEM_1024_CRYPTO_CIPHER_LEN = 1568;

    public static Integer MLKEM_1024_PK_LEN = 1568;
    public static Integer MLKEM_1024_SK_LEN = 3168;
    public static Integer MLKEM_1024_M_LEN = 32;
    public static Integer MLKEM_1024_CIPHER_LEN = 1568;
    public static Integer MLKEM_1024_SHARED_KEY_LEN = 32;

    static {
        if (System.getProperty("os.name").startsWith("Windows")) {
            // Windows based
            try {
                System.load(
                        FileSystems.getDefault()
                                .getPath("./lib/libPQCJNI-cpp.dll") // Dynamic link
                                .normalize().toAbsolutePath().toString());
            } catch (UnsatisfiedLinkError e) {
                System.load(
                        FileSystems.getDefault()
                                .getPath("./lib/libPQCJNI-cpp.lib") // Static link
                                .normalize().toAbsolutePath().toString());
            }
        } else {
            // Unix based
            try {
                System.load(
                        FileSystems.getDefault()
                                .getPath("./lib/libPQCJNI-cpp.so") // Dynamic link
                                .normalize().toAbsolutePath().toString());
            } catch (UnsatisfiedLinkError e) {
                System.load(
                        FileSystems.getDefault()
                                .getPath("./lib/libPQCJNI-cpp.a") // Static link
                                .normalize().toAbsolutePath().toString());
            }
        }
    }

    // ML-KEM-512
    public native void mlkem512CryptoKeygen(byte[] pk, byte[] sk);

    public native void mlkem512Keygen(byte[] pk, byte[] sk);

    public native byte[] mlkem512Crypto(byte[] pk, byte[] m);

    public native byte[] mlkem512DeCrypto(byte[] sk, byte[] cipher);

    public native void mlkem512Encapsulate(byte[] pk, byte[] cipher, byte[] shared_key);

    public native byte[] mlkem512Decapsulate(byte[] sk, byte[] cipher);

    // ML-KEM-768
    public native void mlkem768CryptoKeygen(byte[] pk, byte[] sk);

    public native void mlkem768Keygen(byte[] pk, byte[] sk);

    public native byte[] mlkem768Crypto(byte[] pk, byte[] m);

    public native byte[] mlkem768DeCrypto(byte[] sk, byte[] cipher);

    public native void mlkem768Encapsulate(byte[] pk, byte[] cipher, byte[] shared_key);

    public native byte[] mlkem768Decapsulate(byte[] sk, byte[] cipher);

    // ML-KEM-1024
    public native void mlkem1024CryptoKeygen(byte[] pk, byte[] sk);

    public native void mlkem1024Keygen(byte[] pk, byte[] sk);

    public native byte[] mlkem1024Crypto(byte[] pk, byte[] m);

    public native byte[] mlkem1024DeCrypto(byte[] sk, byte[] cipher);

    public native void mlkem1024Encapsulate(byte[] pk, byte[] cipher, byte[] shared_key);

    public native byte[] mlkem1024Decapsulate(byte[] sk, byte[] cipher);

    public static void testMLKEM512Crypto() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_512_CRYPTO_PK_LEN];
        byte[] sk = new byte[MLKEM_512_CRYPTO_SK_LEN];
        String m1 = "This is A demonstration message.";
        t = System.nanoTime();
        mlkem.mlkem512CryptoKeygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_512 crypto key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] cipher = mlkem.mlkem512Crypto(pk, m1.getBytes());
        timeElapsed = System.nanoTime() - t;
        System.out.printf("crypto cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] m2 = mlkem.mlkem512DeCrypto(sk, cipher);
        System.out.printf("decrypto cost: %f us\n", timeElapsed / 1000.0);
        assert m1.equals(new String(m2));
        System.out.println("m1: "+m1);
        System.out.println("m2: "+  new String(m2));
        System.out.println("=====================================================================================");
    }

    public static void testMLKEM512Capsulate() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_512_PK_LEN];
        byte[] sk = new byte[MLKEM_512_SK_LEN];
        byte[] cipher = new byte[MLKEM_512_CIPHER_LEN];
        byte[] shared_key = new byte[MLKEM_512_SHARED_KEY_LEN];
        t = System.nanoTime();
        mlkem.mlkem512Keygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_512 capsulate key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        mlkem.mlkem512Encapsulate(pk, cipher, shared_key);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("encapsulate cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] shared_key_new = mlkem.mlkem512Decapsulate(sk, cipher);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("decapsulate cost: %f us\n", timeElapsed / 1000.0);
        assert Arrays.toString(shared_key).equals(Arrays.toString(shared_key_new));
        System.out.println("=====================================================================================");
    }

    public static void testMLKEM768Crypto() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_768_CRYPTO_PK_LEN];
        byte[] sk = new byte[MLKEM_768_CRYPTO_SK_LEN];
        String m1 = "This is A demonstration message.";
        t = System.nanoTime();
        mlkem.mlkem768CryptoKeygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_768 crypto key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] cipher = mlkem.mlkem768Crypto(pk, m1.getBytes());
        timeElapsed = System.nanoTime() - t;
        System.out.printf("crypto cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] m2 = mlkem.mlkem768DeCrypto(sk, cipher);
        System.out.printf("decrypto cost: %f us\n", timeElapsed / 1000.0);
        assert m1.equals(new String(m2));
        System.out.println("=====================================================================================");

    }

    public static void testMLKEM768Capsulate() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_768_PK_LEN];
        byte[] sk = new byte[MLKEM_768_SK_LEN];
        byte[] cipher = new byte[MLKEM_768_CIPHER_LEN];
        byte[] shared_key = new byte[MLKEM_768_SHARED_KEY_LEN];
        t = System.nanoTime();
        mlkem.mlkem768Keygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_768 capsulate key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        mlkem.mlkem768Encapsulate(pk, cipher, shared_key);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("encapsulate cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] shared_key_new = mlkem.mlkem768Decapsulate(sk, cipher);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("decapsulate cost: %f us\n", timeElapsed / 1000.0);
        assert Arrays.toString(shared_key).equals(Arrays.toString(shared_key_new));
        System.out.println("=====================================================================================");
    }

    public static void testMLKEM1024Crypto() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_1024_CRYPTO_PK_LEN];
        byte[] sk = new byte[MLKEM_1024_CRYPTO_SK_LEN];
        String m1 = "This is A demonstration message.";
        t = System.nanoTime();
        mlkem.mlkem1024CryptoKeygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_1024 crypto key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] cipher = mlkem.mlkem1024Crypto(pk, m1.getBytes());
        timeElapsed = System.nanoTime() - t;
        System.out.printf("crypto cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] m2 = mlkem.mlkem1024DeCrypto(sk, cipher);
        System.out.printf("decrypto cost: %f us\n", timeElapsed / 1000.0);
        assert m1.equals(new String(m2));
        System.out.println("=====================================================================================");

    }

    private static void testMLKEM1024Capsulate() {
        long t = 0L, timeElapsed = 0L;
        MLKEMJNI mlkem = new MLKEMJNI();
        byte[] pk = new byte[MLKEM_1024_PK_LEN];
        byte[] sk = new byte[MLKEM_1024_SK_LEN];
        byte[] cipher = new byte[MLKEM_1024_CIPHER_LEN];
        byte[] shared_key = new byte[MLKEM_1024_SHARED_KEY_LEN];
        t = System.nanoTime();
        mlkem.mlkem1024Keygen(pk, sk);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("generate ml_kem_1024 capsulate key cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        mlkem.mlkem1024Encapsulate(pk, cipher, shared_key);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("encapsulate cost: %f us\n", timeElapsed / 1000.0);
        t = System.nanoTime();
        byte[] shared_key_new = mlkem.mlkem1024Decapsulate(sk, cipher);
        timeElapsed = System.nanoTime() - t;
        System.out.printf("decapsulate cost: %f us\n", timeElapsed / 1000.0);
        assert Arrays.toString(shared_key).equals(Arrays.toString(shared_key_new));
        System.out.println("=====================================================================================");
    }

    public static void main(String[] args) {
        System.out.println("===============================TEST========================================");
//         long t = 0L, timeElapsed = 0L;
//         MLKEMJNI mlkem = new MLKEMJNI();
//         byte[] pk = new byte[MLKEM_512_PK_LEN];
//         byte[] sk = new byte[MLKEM_512_SK_LEN];
//         byte[] cipher = new byte[MLKEM_512_CIPHER_LEN];
//         byte[] shared_key = new byte[MLKEM_512_SHARED_KEY_LEN];
//         mlkem.mlkem512Keygen(pk, sk);
//         System.out.println(new String(pk));
//         System.out.println(new String(sk));

        testMLKEM512Capsulate();
        testMLKEM512Crypto();
        testMLKEM768Capsulate();
        testMLKEM768Crypto();
        testMLKEM1024Capsulate();
        testMLKEM1024Crypto();
    }
};