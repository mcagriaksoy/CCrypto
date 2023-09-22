// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_AES_H
#define CCRYPTO_AES_H

#include <stddef.h>

typedef enum {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
} ccrypto_aes_size_t;

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
 */
void encrypt_with_aes_cbc(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, size_t *ciphertext_len);

/**
 * Encrypts the given plaintext using AES in ECB mode.
 *
 * @param plaintext The input plaintext to be encrypted.
 * @param plaintext_len The length of the plaintext.
 * @param aes_size The size of the AES key (e.g., 128, 192, or 256 bits).
 * @param key The AES encryption key.
 * @param ciphertext The output buffer to store the encrypted ciphertext.
 * @param ciphertext_len A pointer to the length of the ciphertext buffer.
 */
void encrypt_with_aes_ecb(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key,
            unsigned char *ciphertext, size_t *ciphertext_len);

#endif //CCRYPTO_AES_H