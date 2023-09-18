// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// Cryptographic checksum test file for MD5

extern "C"
{
    #include "../include/checksum/md5.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>

#include "CppUTest/TestHarness.h"

// Test group for MD5
TEST_GROUP(FirstTestGroup)
{
};

TEST(FirstTestGroup, SuccessTest)
{
    uint8_t input[] = "Hello word!";
    uint8_t output[16];
    size_t output_size;
    str_to_md5(input, 5, output, &output_size);
    printf("MD5 length: %lu\n", output_size);
    printf("MD5: ");
    for (size_t i = 0; i < output_size; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
    STRCMP_EQUAL(output, "33173600713d870a9742c764b6517cfb");
}
