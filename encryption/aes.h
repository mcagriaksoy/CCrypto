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

void encrypt_with_aes_cbc(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, size_t *ciphertext_len);

void encrypt_with_aes_ecb(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key,
            unsigned char *ciphertext, size_t *ciphertext_len);

#endif //CCRYPTO_AES_H