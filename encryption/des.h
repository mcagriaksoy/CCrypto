// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DES_H
#define CCRYPTO_DES_H

#include "../common/types.h"
#include <stddef.h>

/**
 * @brief Encrypts the given data using the Triple DES algorithm with ECB method.
 *
 * @param key The encryption key.
 * @param data The data to be encrypted.
 * @param data_length The length of the data to be encrypted.
 * @param encrypted The encrypted data.
 * @return ccrypto_error_type indicating the success or failure of the encryption.
 */
ccrypto_error_type des3_encrypt_with_ecb(unsigned char *key,
                                         unsigned char *data,
                                         size_t data_length,
                                         unsigned char *encrypted);

/**
 * @brief Encrypts the given data using the Triple DES algorithm with CBC method.
 *
 * @param key The encryption key.
 * @param vector The initialization vector required for cbc.
 * @param data The data to be encrypted.
 * @param data_length The length of the data to be encrypted.
 * @param encrypted The encrypted data.
 * @return A ccrypto_error_type indicating the success or failure of the encryption.
 */
ccrypto_error_type des3_encrypt_with_cbc(unsigned char *key,
                                         unsigned char *vector,
                                         unsigned char *data,
                                         size_t data_length,
                                         unsigned char *encrypted);

#endif // CCRYPTO_DES_H