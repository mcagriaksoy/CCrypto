// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "aes.h"
#include <string.h>
#include <openssl/evp.h>


void encrypt_with_aes_cbc(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (plaintext == NULL || key == NULL || iv == NULL || ciphertext == NULL || ciphertext_len == NULL)
    {
        return;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        return;
    }

    EVP_CIPHER *cipher_type = NULL;
    switch(aes_size)
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
            return;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv))
    {
        return;
    }
    
    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len1, plaintext, plaintext_len))
    {
        return;
    }  

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2))
    {
        return;
    }

    *ciphertext_len = (len1 + len2);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_with_aes_ecb(unsigned char *plaintext, int plaintext_len, ccrypto_aes_size_t aes_size, unsigned char *key,
            unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (plaintext == NULL || key == NULL || ciphertext == NULL || ciphertext_len == NULL)
    {
        return;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        return;
    }

    EVP_CIPHER *cipher_type = NULL;
    switch(aes_size)
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
            return;
    }

    /* Initialise key*/
    if(1 != EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, NULL))
    {
        return;
    }
    
    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len1, plaintext, plaintext_len))
    {
        return;
    }  

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2))
    {
        return;
    }

    *ciphertext_len = (len1 + len2);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}