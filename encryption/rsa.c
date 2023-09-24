// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "rsa.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

void encrypt_with_rsa(char *message, char *encrypted_message, char *public_key)
{
    if(message == NULL || encrypted_message == NULL || public_key == NULL)
    {
        return;
    }

    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    if(!(bio = BIO_new_mem_buf(public_key, -1)))
    {
        return;
    }

    if(!(pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)))
    {
        return;
    }

    EVP_PKEY_CTX *ctx = NULL;
    if(!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
    {
        return;
    }

    if(EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        return;
    }

    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        return;
    }

    size_t encrypted_message_len = 0;
    if(EVP_PKEY_encrypt(ctx, NULL, &encrypted_message_len, (unsigned char *)message, strlen(message)) <= 0)
    {
        return;
    }

    if(EVP_PKEY_encrypt(ctx, (unsigned char *)encrypted_message, &encrypted_message_len, (unsigned char *)message, strlen(message)) <= 0)
    {
        return;
    }

    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(bio);
    EVP_PKEY_free(pkey);
}