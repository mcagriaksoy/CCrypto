// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DECRYPT_DES_H
#define CCRYPTO_DECRYPT_DES_H

#include "../common/types.h"
#include <stddef.h>

/**
 * @brief Decrypts data using the Triple DES algorithm in ECB mode.
 *
 * This function decrypts the given data using the Triple DES algorithm in ECB
 * (Electronic Codebook) mode. The decrypted data is stored in the output buffer,
 * and the length of the decrypted data is stored in the output length variable.
 *
 * @param key The encryption key to use for decryption. The key must be 24 bytes long.
 * @param input The data to decrypt.
 * @param input_length The length of the data to decrypt.
 * @param output The output buffer to store the decrypted data.
 * @param output_length A pointer to a variable to store the length of the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 *         If the decryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during decryption, an appropriate error code is returned.
 */
ccrypto_error_type des3_decrypt_with_ecb(
    const uint8_t *key,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t *output_length);

/**
 * @brief Decrypts data using the Triple DES algorithm in CBC mode.
 *
 * This function decrypts the given data using the Triple DES algorithm in CBC
 * (Cipher Block Chaining) mode. The decrypted data is stored in the output buffer,
 * and the length of the decrypted data is stored in the output length variable.
 *
 * @param key The encryption key to use for decryption. The key must be 24 bytes long.
 * @param iv The initialization vector to use for decryption. The IV must be 8 bytes long.
 * @param input The data to decrypt.
 * @param input_length The length of the data to decrypt.
 * @param output The output buffer to store the decrypted data.
 * @param output_length A pointer to a variable to store the length of the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 *         If the decryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during decryption, an appropriate error code is returned.
 */
ccrypto_error_type des3_decrypt_with_cbc(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t *output_length);

#endif // CCRYPTO_DECRYPT_DES_H