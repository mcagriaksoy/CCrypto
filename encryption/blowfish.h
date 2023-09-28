// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_BLOWFISH_H
#define CCRYPTO_BLOWFISH_H

#include "../common/types.h"
#include <stddef.h>

/**
 * @brief Encrypts data using the Blowfish encryption algorithm.
 *
 * @param key The encryption key.
 * @param key_size The size of the encryption key.
 * @param data The data to encrypt.
 * @param data_size The size of the data to encrypt.
 * @param output The buffer to store the encrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the encryption.
 */
ccrypto_error_type ccrypto_blowfish_encrypt(const uint8_t *key, size_t key_size, const uint8_t *data, size_t data_size, uint8_t *output);

#endif //CCRYPTO_BLOWFISH_H