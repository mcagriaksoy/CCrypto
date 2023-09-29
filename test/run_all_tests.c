// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// unit test
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

// checksum
#include "../checksum/md5.h"
#include "../checksum/crc.h"
#include "../checksum/sha3.h"

// encryption
#include "../encryption/aes.h"
#include "../encryption/rsa.h"
#include "../encryption/des.h"
#include "../encryption/blowfish.h"

// decryption
#include "../decryption/aes.h"
#include "../decryption/des.h"
#include "../decryption/blowfish.h"

// common
#include "../common/types.h"

unsigned char plaintext[] = "Hello word!";

void test_all_with_aes_ecb(void) {
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char ciphertext[32];
    size_t ciphertext_len;

    CU_ASSERT_EQUAL(encrypt_with_aes_ecb(plaintext, plaintext_len, aes_size, key, ciphertext, &ciphertext_len), CCRYPTO_SUCCESS);

    uint8_t real_data[] = {0xce, 0xd8, 0x9c, 0x5e, 0x10, 0x96, 0xec, 0xd1,0xd6, 0x79, 0x7f, 0x08, 0x35, 0xe9, 0x5d, 0x61};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++) {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }

    unsigned char gathered_plaintext[32];
    size_t gathered_plaintext_len;
    CU_ASSERT_EQUAL(decrypt_with_aes_ecb(ciphertext, ciphertext_len, aes_size, key, gathered_plaintext, &gathered_plaintext_len), CCRYPTO_SUCCESS);
    for (size_t i = 0; i < gathered_plaintext_len; i++) {
        CU_ASSERT_EQUAL(plaintext[i], gathered_plaintext[i]);
    }
}

void test_all_with_aes_ccb(void) {
    int plaintext_len = strlen(plaintext);
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";
    unsigned char ciphertext[32];
    size_t ciphertext_len;

    encrypt_with_aes_cbc(plaintext, plaintext_len, aes_size, key, iv, ciphertext, &ciphertext_len);
    uint8_t real_data[] = {0x19,0xe3,0xa6,0xeb,0x39,0xfe,0xe2,0x0e,0x92,0xf1,0x00,0xf6,0xf1,0x92,0x56,0xe3};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++) {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }

    unsigned char gathered_plaintext[32];
    size_t gathered_plaintext_len;
    CU_ASSERT_EQUAL(decrypt_with_aes_cbc(ciphertext, ciphertext_len, aes_size, key, iv, gathered_plaintext, &gathered_plaintext_len), CCRYPTO_SUCCESS);
    for (size_t i = 0; i < gathered_plaintext_len; i++) {
        CU_ASSERT_EQUAL(plaintext[i], gathered_plaintext[i]);
    }
}


void test_encrypt_with_rsa(void) {
    char encrypted_message[256];
    char public_key[] = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMe97tXGYHZK3EuTeXJQKxHcYXvR4NM4KxB2h9T4GxJzwzV1\n-----END PUBLIC KEY-----\n"; 
    char real_data[] = "Lw4xGb3IBRUTXBIA+B54rjAzLbWYGuVbGiGvOox0sygtHVAwwoKiYvA7qPEMuY95c30NQQfh2h7V9vc26KOSPg==";

    //CU_ASSERT_EQUAL(encrypt_with_rsa(plaintext, encrypted_message, public_key), CCRYPTO_SUCCESS);

    //CU_ASSERT_STRING_NOT_EQUAL(plaintext, encrypted_message);
    //CU_ASSERT_STRING_EQUAL(encrypted_message, real_data);

    // TODO Fix this test!
}

void test_des_encrypt(void) {
    unsigned char key[] = "012345678910111213140123456789";
    unsigned char encrypted[16];

    unsigned char real_data_ecb[] = {0xDC, 0xE5, 0x11, 0x62, 0xEA, 0x09, 0x86, 0xD7, 0xC4, 0xD7, 0x03, 0x40, 0x62, 0x12,0x08, 0x89};
    CU_ASSERT_EQUAL(des3_encrypt_with_ecb(key, plaintext, encrypted), CCRYPTO_SUCCESS);

    CU_ASSERT_NOT_EQUAL(memcmp(plaintext, encrypted, 8), 0);
    for (size_t i = 0; i < sizeof(real_data_ecb) - 1; i++) {   
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_ecb[i]);
    }

    // cbc TEST!
    // Initialization vector.
    unsigned char iv[] = "01234567";
    CU_ASSERT_EQUAL(des3_encrypt_with_cbc(key, iv, plaintext, encrypted), CCRYPTO_SUCCESS);

    unsigned char real_data_cbc[] = {0x12, 0xAB, 0x02, 0x5B, 0xCC, 0xC3, 0xD8, 0x68, 0x9A, 0xFE, 0xDC, 0xC6, 0xCE, 0xF1, 0xAA, 0xC2};
    for (size_t i = 0; i < sizeof(real_data_cbc) - 1; i++) {   
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_cbc[i]);
    }
}

void test_blowfish_encrypt(void) {
    const uint8_t input_text[] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}; // It supports only 8bytes of data!
    
    const uint8_t key[56] = {
		0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69,
		0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x04, 0x68, 0x91, 0x04, 0xc2, 0xfd,
		0x3b, 0x2f, 0x58, 0x40, 0x23, 0x64, 0x1a, 0xba, 0x61, 0x76,
		0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

    const uint8_t real_data_blowfish[8] = {0xc0, 0x45, 0x04, 0x01, 0x2e, 0x4e, 0x1f, 0x53};

    uint8_t encrypted[32];
    size_t data_length = strlen(input_text);
    CU_ASSERT_EQUAL(ccrypto_blowfish_encrypt(key, sizeof(key), input_text, sizeof(input_text), encrypted), CCRYPTO_SUCCESS);
    CU_ASSERT_NOT_EQUAL(memcmp(input_text, encrypted, data_length), 0);

    for (size_t i = 0; i < sizeof(input_text) - 1; i++) {
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_blowfish[i]);
    }
}

void test_encrypt_ecc(void) {
    const uint8_t public_key[] = {0x04, 0x5d, 0x5e, 0x7a, 0x1c, 0x9d, 0x2c, 0x2d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d, 0x9e, 0x5d, 0x0e, 0x3a, 0x4e, 0x9d, 0x3c, 0x3d};
    const uint8_t data[] = "Hello, world!";
    const size_t data_length = strlen((const char *)data);
    uint8_t encrypted_data[1024];
    size_t encrypted_data_length;

    // Encrypt the data
    ccrypto_error_type result = ccrypto_ecc_encrypt(public_key, data, data_length, encrypted_data, &encrypted_data_length);
    if (result != CCRYPTO_SUCCESS) {
        printf("Encryption failed with error code %d\n", result);
        return 1;
    }

    // Print the encrypted data
    printf("Encrypted data: ");
    for (size_t i = 0; i < encrypted_data_length; i++) {
        printf("%02x", encrypted_data[i]);
    }
    printf("\n");

}

void test_str_to_sha3(void) {
    size_t str_size = strlen(plaintext);
    sha3_type algo_type = SHA3_256;
    uint8_t sha3_value[32];
    size_t sha3_value_size;

    CU_ASSERT_EQUAL(str_to_sha3(plaintext, str_size, algo_type, sha3_value, &sha3_value_size), CCRYPTO_SUCCESS);

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

    CU_ASSERT_EQUAL(str_to_crc(plaintext, str_size, crc_type, crc_value, &crc_value_size) , CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(crc_value_size, 1);
    CU_ASSERT_EQUAL(crc_value[0], 0x35);

    // TODO CRC16 and CRC32 not working!
}

void test_str_to_md5(void) {
    size_t str_size = strlen(plaintext);
    uint8_t md5_value[16];
    size_t md5_value_size;

    CU_ASSERT_EQUAL(str_to_md5(plaintext, str_size, md5_value, &md5_value_size) , CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(md5_value_size, 16);
    uint8_t real_data[] = {0x33,0x17,0x36,0x00,0x71,0x3d,0x87,0x0a,0x97,0x42,0xc7,0x64,0xb6,0x51,0x7c,0xfb};
    for (size_t i = 0; i < md5_value_size; i++) {
        CU_ASSERT_EQUAL(md5_value[i], real_data[i]);
    }
}

// Test main
int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("All tests", NULL, NULL);

    // checksum tests
    CU_add_test(suite, "test_str_to_md5", test_str_to_md5);
    CU_add_test(suite, "test_str_to_crc", test_str_to_crc);
    CU_add_test(suite, "test_str_to_sha3", test_str_to_sha3);

    // encryption - decryption tests
    CU_add_test(suite, "test_all_with_aes_ecb", test_all_with_aes_ecb);
    CU_add_test(suite, "test_all_with_aes_ccb", test_all_with_aes_ccb);

     
    CU_add_test(suite, "test_encrypt_with_rsa", test_encrypt_with_rsa);
    CU_add_test(suite, "test_des_encrypt", test_des_encrypt);
    CU_add_test(suite, "test_blowfish_encrypt", test_blowfish_encrypt);
    CU_add_test(suite, "test_encrypt_ecc", test_encrypt_ecc);

    // Run all tests
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}