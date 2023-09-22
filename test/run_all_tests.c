// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// Include
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../checksum/md5.h"
#include "../checksum/crc.h"
#include "../checksum/sha3.h"
#include "../encryption/aes.h"

void test_encrypt_with_aes_ecb(void) {
    unsigned char plaintext[] = "Hello, world!";
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_128;
    unsigned char key[] = "0123456789abcdef";
    unsigned char ciphertext[128];
    size_t ciphertext_len;

    encrypt_with_aes_ecb(plaintext, plaintext_len, aes_size, key, ciphertext, &ciphertext_len);

    CU_ASSERT_NOT_EQUAL(ciphertext_len, 0);
}

void test_encrypt_with_aes_cbc(void) {
    unsigned char plaintext[] = "Hello, world!";
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_128;
    unsigned char key[] = "0123456789abcdef";
    unsigned char iv[] = "0123456789abcdef";
    unsigned char ciphertext[128];
    size_t ciphertext_len;

    encrypt_with_aes_cbc(plaintext, plaintext_len, aes_size, key, iv, ciphertext, &ciphertext_len);

    CU_ASSERT_NOT_EQUAL(ciphertext_len, 0);
}


void test_str_to_sha3(void) {
    uint8_t str[] = "Hello, world!";
    size_t str_size = strlen(str);
    sha3_type algo_type = SHA3_256;
    uint8_t sha3_value[32];
    size_t sha3_value_size;

    str_to_sha3(str, str_size, algo_type, sha3_value, &sha3_value_size);

    CU_ASSERT_EQUAL(sha3_value_size, 32);
}

void test_str_to_crc(void) {
    uint8_t str[] = "Hello, world!";
    size_t str_size = strlen(str);
    crc_type_t crc_type = CRC32;
    uint8_t crc_value[4];
    size_t crc_value_size;

    str_to_crc(str, str_size, crc_type, crc_value, &crc_value_size);

    CU_ASSERT_EQUAL(crc_value_size, 4);
}

void test_str_to_md5(void) {
    uint8_t str[] = "Hello, world!";
    size_t str_size = strlen(str);
    uint8_t md5_value[16];
    size_t md5_value_size;

    str_to_md5(str, str_size, md5_value, &md5_value_size);

    CU_ASSERT_EQUAL(md5_value_size, 16);
}

// Test
int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("md5_suite", NULL, NULL);
    CU_add_test(suite, "test_str_to_md5", test_str_to_md5);
    CU_add_test(suite, "test_str_to_crc", test_str_to_crc);
    CU_add_test(suite, "test_str_to_sha3", test_str_to_sha3);
    CU_add_test(suite, "test_encrypt_with_aes_ecb", test_encrypt_with_aes_ecb);
    CU_add_test(suite, "test_encrypt_with_aes_cbc", test_encrypt_with_aes_cbc);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return 0;
}