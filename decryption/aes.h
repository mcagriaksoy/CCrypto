/**
 * @file aes.h
 * @author Mehmet Cagri Aksoy
 * @brief This file contains the definition of aes decryption functions used in CCrypto library.
 * @see https://github.com/mcagriaksoy/CCrypto
 *
 */

#ifndef CCRYPTO_DECRYPT_AES_H
#define CCRYPTO_DECRYPT_AES_H

#include "../common/types.h"
#include <stddef.h>

/**
 * @brief Decrypts data using the AES algorithm in CBC mode.
 *
 * This function decrypts the given data using the AES algorithm in CBC
 * (Cipher Block Chaining) mode. The decrypted data is stored in the output buffer,
 * and the length of the decrypted data is stored in the output length variable.
 *
 * @param ciphertext The data to decrypt.
 * @param ciphertext_len The length of the data to decrypt.
 * @param aes_size The size of the AES key to use for decryption.
 * @param key The encryption key to use for decryption. The key length must match the AES key size.
 * @param iv The initialization vector to use for decryption. The IV must be the same length as the AES block size.
 * @param plaintext The output buffer to store the decrypted data.
 * @param plaintext_len A pointer to a variable to store the length of the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 *         If the decryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during decryption, an appropriate error code is returned.
 */
ccrypto_error_type decrypt_with_aes_cbc(unsigned char *ciphertext,
                                        size_t ciphertext_len,
                                        ccrypto_aes_size_t aes_size,
                                        unsigned char *key,
                                        unsigned char *iv,
                                        unsigned char *plaintext,
                                        size_t *plaintext_len);

/**
 * @brief Decrypts data using the AES algorithm in ECB mode.
 *
 * This function decrypts the given data using the AES algorithm in ECB
 * (Electronic Codebook) mode. The decrypted data is stored in the output buffer,
 * and the length of the decrypted data is stored in the output length variable.
 *
 * @param ciphertext The data to decrypt.
 * @param ciphertext_len The length of the data to decrypt.
 * @param aes_size The size of the AES key to use for decryption.
 * @param key The encryption key to use for decryption. The key length must match the AES key size.
 * @param plaintext The output buffer to store the decrypted data.
 * @param plaintext_len A pointer to a variable to store the length of the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 *         If the decryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during decryption, an appropriate error code is returned.
 */
ccrypto_error_type decrypt_with_aes_ecb(unsigned char *ciphertext,
                                        size_t ciphertext_len,
                                        ccrypto_aes_size_t aes_size,
                                        unsigned char *key,
                                        unsigned char *plaintext,
                                        size_t *plaintext_len);

#endif // CCRYPTO_AES_H