/**
 * @file blowfish.c
 * @brief This file contains the implementation of the Blowfish encryption algorithm.
 *
 * The Blowfish algorithm is a symmetric-key block cipher that can be used for encryption and decryption.
 * This implementation was created by Mehmet Cagri Aksoy in 2023 and can be found on GitHub at github.com/mcagriaksoy.
 */

#include "blowfish.h"
#include <openssl/blowfish.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Macro definition for the minimum key size.
 */
#define MIN_KEY_SIZE 4
/**
 * @brief Macro definition for the maximum key size.
 */
#define MAX_KEY_SIZE 56
/**
 * @brief Macro definition for the block size.
 */
#define BLOCK_SIZE 8

ccrypto_error_type ccrypto_blowfish_decrypt(const uint8_t *key,
                                            size_t key_size,
                                            const uint8_t *data,
                                            size_t data_size,
                                            uint8_t *output)
{
    if (key == NULL || data == NULL || output == NULL)
    {
        printf("Error: key, data and output must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (data_size % BLOCK_SIZE != 0)
    {
        printf("Error: data_size must be a multiple of 8\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (key_size < MIN_KEY_SIZE || key_size > MAX_KEY_SIZE)
    {
        printf("Error: key_size must be between 4 and 56\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the Blowfish context with the given key
    BF_KEY bf_key;
    BF_set_key(&bf_key, (int)key_size, key);

    for (size_t i = 0; i < data_size; i += BLOCK_SIZE)
    {
        // Decrypt the data
        BF_ecb_encrypt(data, output, &bf_key, BF_DECRYPT);
    }

    return CCRYPTO_SUCCESS;
}