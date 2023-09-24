// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// Include
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../checksum/md5.h"
#include "../checksum/crc.h"
#include "../checksum/sha3.h"
#include "../encryption/aes.h"
#include "../encryption/rsa.h"
#include "../encryption/des.h"

unsigned char plaintext[] = "Hello word!";

void test_encrypt_with_aes_ecb(void) {
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char ciphertext[128];
    size_t ciphertext_len;

    encrypt_with_aes_ecb(plaintext, plaintext_len, aes_size, key, ciphertext, &ciphertext_len);

    uint8_t real_data[] = {0xce, 0xd8, 0x9c, 0x5e, 0x10, 0x96, 0xec, 0xd1,0xd6, 0x79, 0x7f, 0x08, 0x35, 0xe9, 0x5d, 0x61};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++) {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }
}

void test_encrypt_with_aes_cbc(void) {
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";
    unsigned char ciphertext[128];
    size_t ciphertext_len;

    encrypt_with_aes_cbc(plaintext, plaintext_len, aes_size, key, iv, ciphertext, &ciphertext_len);
    uint8_t real_data[] = {0x19,0xe3,0xa6,0xeb,0x39,0xfe,0xe2,0x0e,0x92,0xf1,0x00,0xf6,0xf1,0x92,0x56,0xe3};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++) {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }
}


void test_str_to_sha3(void) {
    size_t str_size = strlen(plaintext);
    sha3_type algo_type = SHA3_256;
    uint8_t sha3_value[32];
    size_t sha3_value_size;

    str_to_sha3(plaintext, str_size, algo_type, sha3_value, &sha3_value_size);

    CU_ASSERT_EQUAL(sha3_value_size, 32);
    uint8_t real_data[] = {0x26,0xa0,0x3d, 0x18, 0x5f, 0x96, 0x98, 0x9a, 0xb1, 0xb9, 0xdc,0xdd,0x35,\
    0x54,0xa5,0xe8,0xdf,0xdd,0x89,0x86,0xf1,0xcd,0xaf,0x00,0x2c,0x7b,0x98,0xc8,0x8c,0x14,0xf2,0x4f};
    for (size_t i = 0; i < sizeof(real_data)/2; i++) {
        CU_ASSERT_EQUAL(sha3_value[i], real_data[i]);
    }
}

void test_str_to_crc(void) {
    size_t str_size = strlen(plaintext);
    crc_type_t crc_type = CRC8;
    uint8_t crc_value[4];
    size_t crc_value_size;

    str_to_crc(plaintext, str_size, crc_type, crc_value, &crc_value_size);

    CU_ASSERT_EQUAL(crc_value_size, 1);
    CU_ASSERT_EQUAL(crc_value[0], 0x35);

    // TODO CRC16 and CRC32 not working!

}

void test_str_to_md5(void) {
    size_t str_size = strlen(plaintext);
    uint8_t md5_value[16];
    size_t md5_value_size;

    str_to_md5(plaintext, str_size, md5_value, &md5_value_size);

    CU_ASSERT_EQUAL(md5_value_size, 16);
    uint8_t real_data[] = {0x33,0x17,0x36,0x00,0x71,0x3d,0x87,0x0a,0x97,0x42,0xc7,0x64,0xb6,0x51,0x7c,0xfb};
    for (size_t i = 0; i < md5_value_size; i++) {
        CU_ASSERT_EQUAL(md5_value[i], real_data[i]);
    }
}

void test_encrypt_with_rsa(void) {
    char encrypted_message[256];
    char public_key[] = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMe97tXGYHZK3EuTeXJQKxHcYXvR4NM4KxB2h9T4GxJzwzV1\n-----END PUBLIC KEY-----\n"; 
    char real_data[] = "Lw4xGb3IBRUTXBIA+B54rjAzLbWYGuVbGiGvOox0sygtHVAwwoKiYvA7qPEMuY95c30NQQfh2h7V9vc26KOSPg==";

    //encrypt_with_rsa(plaintext, encrypted_message, public_key);

    //CU_ASSERT_STRING_NOT_EQUAL(plaintext, encrypted_message);
    //CU_ASSERT_STRING_EQUAL(encrypted_message, real_data);

    // TODO Fix this test!
}

void test_des_encrypt(void) {
    unsigned char key[] = "012345678910111213140123456789";
    unsigned char encrypted[16];

    unsigned char real_data_ecb[] = {0xDC, 0xE5, 0x11, 0x62, 0xEA, 0x09, 0x86, 0xD7, 0xC4, 0xD7, 0x03, 0x40, 0x62, 0x12,0x08, 0x89};
    des3_encrypt_with_ecb(key, plaintext, encrypted);

    CU_ASSERT_NOT_EQUAL(memcmp(plaintext, encrypted, 8), 0);
    for (size_t i = 0; i < sizeof(real_data_ecb) - 1; i++) {   
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_ecb[i]);
    }

    // cbc TEST!
    // Initialization vector.
    unsigned char iv[] = "01234567";
    des3_encrypt_with_cbc(key, iv, plaintext, encrypted);

    unsigned char real_data_cbc[] = {0x12, 0xAB, 0x02, 0x5B, 0xCC, 0xC3, 0xD8, 0x68, 0x9A, 0xFE, 0xDC, 0xC6, 0xCE, 0xF1, 0xAA, 0xC2};
    for (size_t i = 0; i < sizeof(real_data_cbc) - 1; i++) {   
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_cbc[i]);
    }
}


// Test
int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("All tests", NULL, NULL);
    CU_add_test(suite, "test_str_to_md5", test_str_to_md5);
    CU_add_test(suite, "test_str_to_crc", test_str_to_crc);
    CU_add_test(suite, "test_str_to_sha3", test_str_to_sha3);
    CU_add_test(suite, "test_encrypt_with_aes_ecb", test_encrypt_with_aes_ecb);
    CU_add_test(suite, "test_encrypt_with_rsa", test_encrypt_with_rsa);
    CU_add_test(suite, "test_des_encrypt", test_des_encrypt);
    CU_add_test(suite, "test_encrypt_with_aes_cbc", test_encrypt_with_aes_cbc);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return 0;
}