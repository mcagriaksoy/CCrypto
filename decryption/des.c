// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "des.h"
#include <openssl/des.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

ccrypto_error_type des3_decrypt_with_ecb(const uint8_t *key,
                                         const uint8_t *input,
                                         size_t input_length,
                                         uint8_t *output,
                                         size_t *output_length)
{
    if (key == NULL || input == NULL || output == NULL)
    {
        printf("Invalid argument(s) in des3_decrypt_with_ecb()\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (input_length % 8 != 0)
    {
        printf("Invalid input length in des3_decrypt_with_ecb()\n");
        return CCRYPTO_ERROR_INVALID_MESSAGE;
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
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, output, &len1, input, input_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, output + len1, &len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *output_length = len1 + len2;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return CCRYPTO_SUCCESS;
}

ccrypto_error_type des3_decrypt_with_cbc(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t *output_length)
{
    if (key == NULL || input == NULL || output == NULL)
    {
        printf("Invalid argument(s) in des3_decrypt_with_ecb()\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (input_length % 8 != 0)
    {
        printf("Invalid input length in des3_decrypt_with_ecb()\n");
        return CCRYPTO_ERROR_INVALID_MESSAGE;
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
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, output, &len1, input, input_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, output + len1, &len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    *output_length = len1 + len2;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return CCRYPTO_SUCCESS;
}