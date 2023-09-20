// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy
// This is a C api that contains cryptographic functions.

#include "md5.h"
#include "sha3.h"
#include "crc.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void md5_test(void)
{
    uint8_t input[] = "Hello word!";
    // Test Data: "33173600713d870a9742c764b6517cfb"
    // The values of the MD5 hash are stored in the output array should be the same as the test data.
    uint8_t output[16];
    size_t output_size;
    str_to_md5(input, sizeof(input) - 1, output, &output_size);
    printf("MD5 length: %lu\n", output_size);
    printf("MD5: ");
    for (size_t i = 0; i < output_size; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}

void sha3_test(void)
{
    uint8_t input[] = "Hello word!";
    // Test Data: "26a03d185f96989ab1b9dcdd3554a5e8dfdd8986f1cdaf002c7b98c88c14f24f"
    // The values of the sha3 hash are stored in the output array should be the same as the test data.
    uint8_t output[128];
    size_t output_size;
    str_to_sha3(input, sizeof(input) - 1, 256, output, &output_size);
    printf("SHA length: %lu\n", output_size);
    printf("SHA: ");
    for (size_t i = 0; i < output_size; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}

void crc_test(void)
{
    uint8_t input[] = "Hello_word!";
    // Test Data: "crc 8: 0x76"
    // The values of the crc are stored in the output array should be the same as the test data.
    uint8_t output[128];
    size_t output_size;
    str_to_crc(input, sizeof(input) - 1, CRC8, output, &output_size);
    printf("CRC length: %lu\n", output_size);
    printf("CRC: 0x");
    for (size_t i = 0; i < output_size; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}

// Test
int main()
{
    md5_test();
    sha3_test();
    crc_test();
    return 0;
}