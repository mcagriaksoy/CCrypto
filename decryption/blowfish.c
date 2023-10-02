// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "blowfish.h"
#include <openssl/blowfish.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

ccrypto_error_type ccrypto_blowfish_decrypt(const uint8_t *key, size_t key_size,
                                            const uint8_t *data, size_t data_size,
                                            uint8_t *output)
{
    if (key == NULL || data == NULL || output == NULL)
    {
        printf("Error: key, data and output must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (data_size % 8 != 0)
    {
        printf("Error: data_size must be a multiple of 8\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (key_size < 4 || key_size > 56)
    {
        printf("Error: key_size must be between 4 and 56\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the Blowfish context with the given key
    BF_KEY bf_key;
    BF_set_key(&bf_key, (int)key_size, key);

    for (int i = 0; i < data_size; i += 8)
    {
        // Decrypt the data
        BF_ecb_encrypt(data, output, &bf_key, BF_DECRYPT);
    }

    return CCRYPTO_SUCCESS;
}