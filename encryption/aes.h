/**
 * @file aes.h
 * @author Mehmet Cagri Aksoy
 * @brief This file contains the definition of aes encryption functions used in CCrypto library.
 * @see https://github.com/mcagriaksoy/CCrypto
 *
 */

#ifndef CCRYPTO_AES_H
#define CCRYPTO_AES_H

#include <stddef.h>

#include "../common/types.h"

/**
 * Encrypts the given plaintext using AES in CBC mode.
 *
 * @param plaintext The input plaintext to be encrypted.
 * @param plaintext_len The length of the plaintext.
 * @param aes_size The size of the AES key (e.g., 128, 192, or 256 bits).
 * @param key The AES encryption key.
 * @param iv The initialization vector (IV) for CBC mode.
 * @param ciphertext The output buffer to store the encrypted ciphertext.
 * @param ciphertext_len A pointer to the length of the ciphertext buffer.
 * @return ccrypto_error_type
 */
ccrypto_error_type encrypt_with_aes_cbc(const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        ccrypto_aes_size_t aes_size,
                                        uint8_t *key,
                                        uint8_t *iv,
                                        uint8_t *ciphertext,
                                        size_t *ciphertext_len);

/**
 * Encrypts the given plaintext using AES in ECB mode.
 *
 * @param plaintext The input plaintext to be encrypted.
 * @param plaintext_len The length of the plaintext.
 * @param aes_size The size of the AES key (e.g., 128, 192, or 256 bits).
 * @param key The AES encryption key.
 * @param ciphertext The output buffer to store the encrypted ciphertext.
 * @param ciphertext_len A pointer to the length of the ciphertext buffer.
 * @return ccrypto_error_type
 */
ccrypto_error_type encrypt_with_aes_ecb(const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        ccrypto_aes_size_t aes_size,
                                        uint8_t *key,
                                        uint8_t *ciphertext,
                                        size_t *ciphertext_len);

#endif // CCRYPTO_AES_H