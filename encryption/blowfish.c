// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "blowfish.h"
#include <string.h>
#include <openssl/blowfish.h>
#include <stdio.h>
#include <stddef.h>

ccrypto_error_type ccrypto_blowfish_encrypt(const uint8_t *key, size_t key_size, const uint8_t *data, uint8_t *output)
{
    if (key == NULL || data == NULL || output == NULL)
    {
        printf("Error: key, data and output must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the Blowfish context with the given key
    BF_KEY bf_key;
    BF_set_key(&bf_key, (int)key_size, key);

    // Encrypt the data
    BF_ecb_encrypt(data, output, &bf_key, BF_ENCRYPT);

    return CCRYPTO_SUCCESS;
}