/**
 * @file md5.h
 * @author Mehmet Cagri Aksoy
 * @brief This file contains the definition of MD5 checksum functions used in CCrypto library.
 * @see https://github.com/mcagriaksoy/CCrypto
 *
 */
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
 * @param plaintext The string to hash.
 * @param plaintext_size The length of the string to hash.
 * @param md5_value The output buffer to store the hash value.
 * @param md5_value_size A pointer to a variable to store the length of the hash value.
 *
 * @return A ccrypto_error_type indicating the success or failure of the hashing.
 *         If the hashing was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during hashing, an appropriate error code is returned.
 */
ccrypto_error_type str_to_md5(const uint8_t *plaintext,
                              size_t plaintext_size,
                              uint8_t *md5_value,
                              size_t *md5_value_size);

#endif // CCRYPTO_MD5_H