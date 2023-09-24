// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "des.h"

#include <string.h>
#include <openssl/evp.h>

void des_encrypt(unsigned char *key, unsigned char *data, unsigned char *encrypted)
{
    if (key == NULL || data == NULL || encrypted == NULL)
    {
        return;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        return;
    }

    /* Initialise key and IV */
    /* EDE3 represents the triple des implementation */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL))
    {
        return;
    }
    
    int len1 = 0;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, encrypted, &len1, data, strlen(data)))
    {
        return;
    }  

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    int len2 = 0;
    if(1 != EVP_EncryptFinal_ex(ctx, encrypted + len1, &len2))
    {
        return;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}