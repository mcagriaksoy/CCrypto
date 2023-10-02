// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_MD5_H
#define CCRYPTO_MD5_H

#include <stdint.h>
#include <stdlib.h>

#include "../common/types.h"

/**
 * @brief Computes the MD5 hash of a string.
 *
 * This function computes the MD5 hash of the given string. The resulting hash value
 * is stored in the output buffer, and the length of the hash value is stored in the
 * output length variable.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param md5_value The output buffer to store the hash value.
 * @param md5_value_size A pointer to a variable to store the length of the hash value.
 *
 * @return A ccrypto_error_type indicating the success or failure of the hashing.
 *         If the hashing was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during hashing, an appropriate error code is returned.
 */
ccrypto_error_type str_to_md5(uint8_t *str, size_t str_size, uint8_t *md5_value, size_t *md5_value_size);

#endif // CCRYPTO_MD5_H