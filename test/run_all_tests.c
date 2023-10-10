// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// unit test
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

// checksum
#include "../checksum/crc.h"
#include "../checksum/md5.h"
#include "../checksum/sha3.h"

// encryption
#include "../encryption/aes.h"
#include "../encryption/blowfish.h"
#include "../encryption/des.h"
#include "../encryption/rsa.h"

// decryption
#include "../decryption/aes.h"
#include "../decryption/blowfish.h"
#include "../decryption/des.h"

// common
#include "../common/types.h"

unsigned char plaintext[] = "Hello word!";
size_t plaintext_len = 11U;

void test_all_with_aes_ecb(void)
{
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char ciphertext[32];
    size_t ciphertext_len;

    CU_ASSERT_EQUAL(encrypt_with_aes_ecb(plaintext, plaintext_len, aes_size, key, ciphertext, &ciphertext_len), CCRYPTO_SUCCESS);

    uint8_t real_data[] = {0xce, 0xd8, 0x9c, 0x5e, 0x10, 0x96, 0xec, 0xd1,
                           0xd6, 0x79, 0x7f, 0x08, 0x35, 0xe9, 0x5d, 0x61};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++)
    {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }

    unsigned char gathered_plaintext[32];
    size_t gathered_plaintext_len;
    CU_ASSERT_EQUAL(decrypt_with_aes_ecb(ciphertext, ciphertext_len, aes_size, key, gathered_plaintext, &gathered_plaintext_len), CCRYPTO_SUCCESS);
    for (size_t i = 0; i < gathered_plaintext_len; i++)
    {
        CU_ASSERT_EQUAL(plaintext[i], gathered_plaintext[i]);
    }
}

void test_all_with_aes_ccb(void)
{
    ccrypto_aes_size_t aes_size = AES_256;
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";
    unsigned char ciphertext[32];
    size_t ciphertext_len;

    encrypt_with_aes_cbc(plaintext, plaintext_len, aes_size, key, iv, ciphertext, &ciphertext_len);
    uint8_t real_data[] = {0x19, 0xe3, 0xa6, 0xeb, 0x39, 0xfe, 0xe2, 0x0e,
                           0x92, 0xf1, 0x00, 0xf6, 0xf1, 0x92, 0x56, 0xe3};
    CU_ASSERT_EQUAL(ciphertext_len, 16);
    for (size_t i = 0; i < sizeof(real_data); i++)
    {
        CU_ASSERT_EQUAL(ciphertext[i], real_data[i]);
    }

    unsigned char gathered_plaintext[32];
    size_t gathered_plaintext_len;
    CU_ASSERT_EQUAL(decrypt_with_aes_cbc(ciphertext, ciphertext_len, aes_size, key, iv, gathered_plaintext, &gathered_plaintext_len), CCRYPTO_SUCCESS);
    for (size_t i = 0; i < gathered_plaintext_len; i++)
    {
        CU_ASSERT_EQUAL(plaintext[i], gathered_plaintext[i]);
    }
}

void test_all_with_rsa(void)
{
    char encrypted_message[256];
    char public_key[] = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMe97tXGYHZK3EuTeXJQKxHcYXvR4NM4KxB2h9T4GxJzwzV1\n-----END PUBLIC KEY-----\n";
    char real_data[] = "Lw4xGb3IBRUTXBIA+B54rjAzLbWYGuVbGiGvOox0sygtHVAwwoKiYvA7qPEMuY95c30NQQfh2h7V9vc26KOSPg==";

    // CU_ASSERT_EQUAL(encrypt_with_rsa(plaintext, encrypted_message, public_key), CCRYPTO_SUCCESS);

    // CU_ASSERT_STRING_NOT_EQUAL(plaintext, encrypted_message);
    // CU_ASSERT_STRING_EQUAL(encrypted_message, real_data);

    // TODO Fix this test!
}

void test_all_3des(void)
{
    unsigned char key[] = "012345678910111213140123456789";
    unsigned char encrypted[16];

    unsigned char real_data_ecb[] = {0xDC, 0xE5, 0x11, 0x62, 0xEA, 0x09, 0x86, 0xD7,
                                     0xC4, 0xD7, 0x03, 0x40, 0x62, 0x12, 0x08, 0x89};
    CU_ASSERT_EQUAL(des3_encrypt_with_ecb(key, plaintext, plaintext_len, encrypted), CCRYPTO_SUCCESS);

    CU_ASSERT_NOT_EQUAL(memcmp(plaintext, encrypted, 8), 0);
    for (size_t i = 0; i < sizeof(real_data_ecb) - 1; i++)
    {
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_ecb[i]);
    }

    // Decrypt the data
    unsigned char decrypted[16];
    size_t decrypted_len;
    CU_ASSERT_EQUAL(des3_decrypt_with_ecb(key, encrypted, sizeof(encrypted), decrypted, &decrypted_len),
                    CCRYPTO_SUCCESS);

    for (size_t i = 0; i < decrypted_len; i++)
    {
        CU_ASSERT_EQUAL((int)decrypted[i], (int)plaintext[i]);
    }

    // cbc TEST!
    // Initialization vector.
    unsigned char iv[] = "01234567";
    CU_ASSERT_EQUAL(des3_encrypt_with_cbc(key, iv, plaintext, plaintext_len, encrypted),
                    CCRYPTO_SUCCESS);

    unsigned char real_data_cbc[] = {0x12, 0xAB, 0x02, 0x5B, 0xCC, 0xC3, 0xD8, 0x68,
                                     0x9A, 0xFE, 0xDC, 0xC6, 0xCE, 0xF1, 0xAA, 0xC2};
    for (size_t i = 0; i < sizeof(real_data_cbc) - 1; i++)
    {
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_cbc[i]);
    }

    // Decrypt the data
    CU_ASSERT_EQUAL(des3_decrypt_with_cbc(key, iv, encrypted, sizeof(encrypted), decrypted, &decrypted_len),
                    CCRYPTO_SUCCESS);
    for (size_t i = 0; i < decrypted_len; i++)
    {
        CU_ASSERT_EQUAL((int)decrypted[i], (int)plaintext[i]);
    }
}

void test_all_blowfish(void)
{
    const uint8_t input_text[] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}; // It supports only 8bytes of data!

    const uint8_t key[56] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69,
        0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x04, 0x68, 0x91, 0x04, 0xc2, 0xfd,
        0x3b, 0x2f, 0x58, 0x40, 0x23, 0x64, 0x1a, 0xba, 0x61, 0x76,
        0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    const uint8_t real_data_blowfish[8] = {0xc0, 0x45, 0x04, 0x01, 0x2e, 0x4e, 0x1f, 0x53};

    uint8_t encrypted[32];
    size_t data_length = strlen(input_text);
    CU_ASSERT_EQUAL(ccrypto_blowfish_encrypt(key, sizeof(key), input_text, sizeof(input_text), encrypted),
                    CCRYPTO_SUCCESS);
    CU_ASSERT_NOT_EQUAL(memcmp(input_text, encrypted, data_length), 0);

    for (size_t i = 0; i < sizeof(input_text) - 1; i++)
    {
        CU_ASSERT_EQUAL((int)encrypted[i], (int)real_data_blowfish[i]);
    }

    uint8_t decrypted[32];
    CU_ASSERT_EQUAL(ccrypto_blowfish_decrypt(key, sizeof(key), encrypted, sizeof(encrypted), decrypted),
                    CCRYPTO_SUCCESS);
    CU_ASSERT_NOT_EQUAL(memcmp(input_text, decrypted, data_length), 0);

    for (size_t i = 0; i < sizeof(input_text) - 1; i++)
    {
        CU_ASSERT_EQUAL((int)decrypted[i], (int)input_text[i]);
    }
}

void test_all_ecc(void)
{
    const uint8_t public_key[] = {0x04, 0xa0, 0x15, 0x32, 0xa3, 0xc0, 0x90, 0x00, 0x53, 0xde, 0x60, 0xfb,
                                  0xef, 0xef, 0xcc, 0xa5, 0x87, 0x93, 0x30, 0x15, 0x98, 0xd3, 0x08, 0xb4,
                                  0x1e, 0x6f, 0x4e, 0x36, 0x4e, 0x38, 0x8c, 0x27, 0x11, 0xbe, 0xf4, 0x32,
                                  0xc5, 0x99, 0x14, 0x8c, 0x94, 0x14, 0x3d, 0x4f, 0xf4, 0x6c, 0x2c, 0xb7,
                                  0x3e, 0x3e, 0x6a, 0x41, 0xd7, 0xee, 0xf2, 0x3c, 0x04, 0x7e, 0xa1, 0x1e,
                                  0x60, 0x66, 0x7d, 0xe4, 0x25};

    const uint8_t private_key[] = {0x11, 0xb5, 0x73, 0x7c, 0xf9, 0xd9, 0x3f, 0x17, 0xc0, 0xcb, 0x1a, 0x84,
                                   0x65, 0x5d, 0x39, 0x95, 0xa0, 0x28, 0x24, 0x09, 0x7e, 0xff, 0xa5, 0xed,
                                   0xd8, 0xee, 0x26, 0x38, 0x1e, 0xb5, 0xd6, 0xc3};

    // const size_t data_length = strlen((const char *)plaintext);
    // uint8_t encrypted_data[1024];
    // size_t encrypted_data_length;

    // TODO fix the tests!
    // Encrypt the data
    // ccrypto_ecc_encrypt(public_key, plaintext, data_length, encrypted_data, &encrypted_data_length);

    // Decrypt the data
    // uint8_t decrypted_data[1024];
    // size_t decrypted_data_length;
    // ccrypto_ecc_decrypt(private_key, encrypted_data, encrypted_data_length, decrypted_data, &decrypted_data_length);

    // Print the decrypted data
    // printf("Decrypted data: ");
    // for (size_t i = 0; i < data_length; i++)
    //{
    //    printf("%c", decrypted_data[i]);
    //}
    // printf("\n");
}

void test_str_to_sha3(void)
{
    sha3_type algo_type = SHA3_256;
    uint8_t sha3_value[32];
    size_t sha3_value_size;

    CU_ASSERT_EQUAL(str_to_sha3(plaintext, plaintext_len, algo_type, sha3_value, &sha3_value_size), CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(sha3_value_size, 32);
    uint8_t real_data[] = {0x26, 0xa0, 0x3d, 0x18, 0x5f, 0x96, 0x98, 0x9a, 0xb1, 0xb9, 0xdc, 0xdd, 0x35,
                           0x54, 0xa5, 0xe8, 0xdf, 0xdd, 0x89, 0x86, 0xf1, 0xcd, 0xaf, 0x00, 0x2c, 0x7b,
                           0x98, 0xc8, 0x8c, 0x14, 0xf2, 0x4f};
    for (size_t i = 0; i < sizeof(real_data) / 2; i++)
    {
        CU_ASSERT_EQUAL(sha3_value[i], real_data[i]);
    }
}

void test_str_to_crc(void)
{
    // TEST CRC8 ALGORITHM
    crc_type_t crc_type = CRC8;
    uint8_t crc_value[8];
    size_t crc_value_size;

    CU_ASSERT_EQUAL(str_to_crc(plaintext, plaintext_len, crc_type, crc_value, &crc_value_size), CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(crc_value_size, 1);
    CU_ASSERT_EQUAL(crc_value[0], 53);

    // TEST CRC16/AUG-CCITT ALGORITHM
    crc_type = CRC16;

    CU_ASSERT_EQUAL(str_to_crc(plaintext, plaintext_len, crc_type, crc_value, &crc_value_size), CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(crc_value_size, 2);
    uint8_t real_data[] = {0x59, 0xd4};

    for (size_t i = 0; i < crc_value_size; i++)
    {
        CU_ASSERT_EQUAL(crc_value[i], real_data[i]);
    }

    // TEST CRC-32/JAMCRC ALGORITHM
    crc_type = CRC32;

    CU_ASSERT_EQUAL(str_to_crc(plaintext, plaintext_len, crc_type, crc_value, &crc_value_size), CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(crc_value_size, 4);
    uint8_t real_data2[] = {0xba, 0x5e, 0x46, 0xba};

    for (size_t i = 0; i < crc_value_size; i++)
    {
        CU_ASSERT_EQUAL(crc_value[i], real_data2[i]);
    }
}

void test_str_to_md5(void)
{
    uint8_t md5_value[16];
    size_t md5_value_size;

    CU_ASSERT_EQUAL(str_to_md5(plaintext, plaintext_len, md5_value, &md5_value_size), CCRYPTO_SUCCESS);

    CU_ASSERT_EQUAL(md5_value_size, 16);
    uint8_t real_data[] = {0x33, 0x17, 0x36, 0x00, 0x71, 0x3d, 0x87, 0x0a, 0x97,
                           0x42, 0xc7, 0x64, 0xb6, 0x51, 0x7c, 0xfb};
    for (size_t i = 0; i < md5_value_size; i++)
    {
        CU_ASSERT_EQUAL(md5_value[i], real_data[i]);
    }
}

// Test main
int main()
{
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("All tests", NULL, NULL);

    // checksum tests
    CU_add_test(suite, "test_str_to_md5", test_str_to_md5);
    CU_add_test(suite, "test_str_to_crc", test_str_to_crc);
    CU_add_test(suite, "test_str_to_sha3", test_str_to_sha3);

    // encryption - decryption tests
    CU_add_test(suite, "test_all_with_aes_ecb", test_all_with_aes_ecb);
    CU_add_test(suite, "test_all_with_aes_ccb", test_all_with_aes_ccb);
    CU_add_test(suite, "test_all_blowfish", test_all_blowfish);
    // CU_add_test(suite, "test_all_ecc", test_all_ecc); TODO Fix!
    CU_add_test(suite, "test_all_with_rsa", test_all_with_rsa);
    CU_add_test(suite, "test_all_3des", test_all_3des);

    // Run all tests
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}