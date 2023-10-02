// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_SHA3_H
#define CCRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>

#include "../common/types.h"

// sha3 types.
typedef enum
{
    SHA3_224 = 224,
    SHA3_256 = 256,
    SHA3_384 = 384,
    SHA3_512 = 512
} sha3_type;

/**
 * @brief Computes the SHA-3 hash of a string.
 *
 * This function computes the SHA-3 hash of the given string using the specified
 * SHA-3 algorithm type. The resulting hash value is stored in the output buffer,
 * and the length of the hash value is stored in the output length variable.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param algo_type The SHA-3 algorithm type to use for hashing.
 * @param sha3_value The output buffer to store the hash value.
 * @param sha3_value_size A pointer to a variable to store the length of the hash value.
 *
 * @return A ccrypto_error_type indicating the success or failure of the hashing.
 *         If the hashing was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during hashing, an appropriate error code is returned.
 */
ccrypto_error_type str_to_sha3(uint8_t *str, size_t str_size, sha3_type algo_type,
                               uint8_t *sha3_value, size_t *sha3_value_size);

#endif // CCRYPTO_SHA3_H