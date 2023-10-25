/**
 * @file des.c
 * @brief Implementation of the Data Encryption Standard (DES) algorithm.
 *
 * This file contains the implementation of the DES algorithm, which is a symmetric-key block cipher
 * used for encryption and decryption of data. The code was created by Mehmet Cagri Aksoy in 2023 and
 * can be found on GitHub at github.com/mcagriaksoy.
 */

#include "des.h"

#include <openssl/evp.h>
#include <string.h>

#include "../common/types.h"

ccrypto_error_type des3_encrypt_with_ecb(const uint8_t *key,
                                         const uint8_t *data,
                                         size_t data_length,
                                         uint8_t *encrypted)
{
    if (key == NULL || data == NULL || encrypted == NULL)
    {
        printf("Error: key, data and encrypted must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Initialise key and IV */
    /* EDE3 represents the triple des implementation */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, encrypted, &len1, data, (int)data_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted + len1, &len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return CCRYPTO_SUCCESS;
}

ccrypto_error_type des3_encrypt_with_cbc(const uint8_t *key,
                                         const uint8_t *vector,
                                         const uint8_t *data,
                                         size_t data_length,
                                         uint8_t *encrypted)
{
    if (key == NULL || data == NULL || encrypted == NULL || vector == NULL)
    {
        printf("Error: key, data, vector and encrypted must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Initialise key and IV */
    /* EDE3 represents the triple des implementation */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, vector))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, encrypted, &len1, data, (int)data_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted + len1, &len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return CCRYPTO_SUCCESS;
}