// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DECRYPT_AES_H
#define CCRYPTO_DECRYPT_AES_H

#include "../common/types.h"
#include <stddef.h>

ccrypto_error_type decrypt_with_aes_cbc(unsigned char *ciphertext, size_t ciphertext_len, ccrypto_aes_size_t aes_size, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext, size_t *plaintext_len);

ccrypto_error_type decrypt_with_aes_ecb(unsigned char *ciphertext, size_t ciphertext_len, ccrypto_aes_size_t aes_size, unsigned char *key,
            unsigned char *plaintext, size_t *plaintext_len);

#endif //CCRYPTO_AES_H