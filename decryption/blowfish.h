// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DECRYPT_BLOWFISH_H
#define CCRYPTO_DECRYPT_BLOWFISH_H

#include "../common/types.h"
#include <stddef.h>

/**
 * @brief Decrypts data using the Blowfish decryption algorithm.
 *
 * @param key The decryption key.
 * @param key_size The size of the decryption key.
 * @param data The data to decrypt.
 * @param data_size The size of the data to decrypt.
 * @param output The buffer to store the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 */
ccrypto_error_type ccrypto_blowfish_decrypt(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t *output);

#endif // CCRYPTO_DECRYPT_BLOWFISH_H