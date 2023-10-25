/**
 * @file aes.c
 * @brief Implementation of the Advanced Encryption Standard (AES) algorithm.
 *
 * This file contains the implementation of the AES algorithm, which is a widely used
 * symmetric encryption algorithm. The implementation is created by Mehmet Cagri Aksoy
 * in 2023 and can be found on GitHub at github.com/mcagriaksoy.
 */

#include "aes.h"
#include <openssl/evp.h>
#include <string.h>

ccrypto_error_type encrypt_with_aes_cbc(const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        ccrypto_aes_size_t aes_size,
                                        uint8_t *key,
                                        uint8_t *iv,
                                        uint8_t *ciphertext,
                                        size_t *ciphertext_len)
{
    if (plaintext == NULL || key == NULL || iv == NULL || ciphertext == NULL || ciphertext_len == NULL)
    {
        printf("Error: plaintext, key, iv, ciphertext and ciphertext_len must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
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

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv))
    {
        printf("Error: EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len1, plaintext, plaintext_len))
    {
        printf("Error: EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2))
    {
        printf("Error: EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *ciphertext_len = (len1 + len2);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return CCRYPTO_SUCCESS;
}

ccrypto_error_type encrypt_with_aes_ecb(const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        ccrypto_aes_size_t aes_size,
                                        uint8_t *key,
                                        uint8_t *ciphertext,
                                        size_t *ciphertext_len)
{
    if (plaintext == NULL || key == NULL || ciphertext == NULL || ciphertext_len == NULL)
    {
        printf("Error: plaintext, key, ciphertext and ciphertext_len must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
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

    /* Initialise key*/
    if (1 != EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, NULL))
    {
        printf("Error: EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len1, plaintext, plaintext_len))
    {
        printf("Error: EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2))
    {
        printf("Error: EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *ciphertext_len = (len1 + len2);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return CCRYPTO_SUCCESS;
}