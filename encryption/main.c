// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy
// This is a C api that contains cryptographic functions.

#include "aes.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>

void aes_test_cbc(void)
{
    uint8_t input[] = "Hello word!";
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";
    char output[256];
    // Test Data: "19 e3 a6 eb 39 fe e2 0e-92 f1 00 f6 f1 92 56 e"
    // The values of the aes hash are stored in the output array should be the same as the test data.
    size_t output_len;
    encrypt_with_aes_cbc(input, sizeof(input) - 1, AES_256, key, iv, output, &output_len);
    printf("AES cipher length: %lu\n", output_len);
    printf("Encrypted message: ");
    BIO_dump_fp(stdout, output, output_len);
    printf("\n");
}

void aes_test_ecb(void)
{
    uint8_t input[] = "Hello word!";
    unsigned char key[] = "01234567890123456789012345678901";
    char output[256];
    // Test Data: "ce d8 9c 5e 10 96 ec d1-d6 79 7f 08 35 e9 5d 61"
    // The values of the aes hash are stored in the output array should be the same as the test data.
    size_t output_len;
    encrypt_with_aes_ecb(input, sizeof(input) - 1, AES_256, key, output, &output_len);
    printf("AES cipher length: %lu\n", output_len);
    printf("Encrypted message: ");
    BIO_dump_fp(stdout, output, output_len);
    printf("\n");
}

// Test
int main()
{
    aes_test_cbc();
    aes_test_ecb();
    return 0;
}