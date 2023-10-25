/**
 * @file aes.c
 * @brief This file contains the implementation of the AES decryption algorithm.
 *
 * This file provides the implementation of the AES decryption algorithm, created by Mehmet Cagri Aksoy in 2023.
 * The code can be found on GitHub at github.com/mcagriaksoy.
 */

#include "aes.h"
#include <openssl/evp.h>
#include <string.h>

ccrypto_error_type decrypt_with_aes_cbc(unsigned char *ciphertext, size_t ciphertext_len,
                                        ccrypto_aes_size_t aes_size,
                                        unsigned char *key,
                                        unsigned char *iv,
                                        unsigned char *plaintext, size_t *plaintext_len)
{
    if (ciphertext == NULL || plaintext_len == NULL || key == NULL || iv == NULL || plaintext == NULL)
    {
        printf("Invalid argument(s) in decrypt_with_aes_cbc()\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    const EVP_CIPHER *cipher_type = NULL;
    switch (aes_size)
    {
    case AES_128:
        cipher_type = EVP_aes_128_cbc();
        break;
    case AES_192:
        cipher_type = EVP_aes_192_cbc();
        break;
    case AES_256:
        cipher_type = EVP_aes_256_cbc();
        break;
    default:
        printf("Error: Invalid aes size.\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Initialise key and IV */
    if (1 != EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv))
    {
        printf("Error: EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len1, ciphertext, ciphertext_len))
    {
        printf("Error: EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len2 = 0;
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len1, &len2))
    {
        printf("Error: EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *plaintext_len = (len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return CCRYPTO_SUCCESS;
}

ccrypto_error_type decrypt_with_aes_ecb(unsigned char *ciphertext, size_t ciphertext_len,
                                        ccrypto_aes_size_t aes_size, unsigned char *key,
                                        unsigned char *plaintext, size_t *plaintext_len)
{
    if (ciphertext == NULL || plaintext_len == NULL || key == NULL || plaintext == NULL)
    {
        printf("Invalid argument(s) in decrypt_with_aes_ecb()\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    const EVP_CIPHER *cipher_type = NULL;
    switch (aes_size)
    {
    case AES_128:
        cipher_type = EVP_aes_128_ecb();
        break;
    case AES_192:
        cipher_type = EVP_aes_192_ecb();
        break;
    case AES_256:
        cipher_type = EVP_aes_256_ecb();
        break;
    default:
        printf("Error: Invalid aes size.\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Initialise key and IV */
    if (1 != EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, NULL))
    {
        printf("Error: EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len1, ciphertext, ciphertext_len))
    {
        printf("Error: EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len2 = 0;
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len1, &len2))
    {
        printf("Error: EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *plaintext_len = (len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return CCRYPTO_SUCCESS;
}