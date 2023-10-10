// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_CRC_H
#define CCRYPTO_CRC_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../common/types.h"

/**
 * @brief Computes the CRC hash of a string.
 *
 * This function computes the CRC hash of the given string using the specified
 * CRC algorithm type. The resulting hash value is stored in the output buffer,
 * and the length of the hash value is stored in the output length variable.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param crc_type The CRC algorithm type to use for hashing.
 * @param crc_value The output buffer to store the hash value.
 * @param crc_value_size A pointer to a variable to store the length of the hash value.
 *
 * @return A ccrypto_error_type indicating the success or failure of the hashing.
 *         If the hashing was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during hashing, an appropriate error code is returned.
 */
ccrypto_error_type str_to_crc(uint8_t *str,
                              size_t str_size,
                              crc_type_t crc_type,
                              uint8_t *crc_value,
                              size_t *crc_value_size);

#endif // CCRYPTO_CRC_H