/**
 * @file rsa.c
 * @brief This file contains the implementation of RSA encryption algorithm.
 *
 * This file provides the implementation of RSA encryption algorithm, which is a widely used public-key
 * cryptosystem. The implementation is created by Mehmet Cagri Aksoy in 2023 and can be found on his
 * GitHub profile at github.com/mcagriaksoy.
 */

#include "rsa.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

ccrypto_error_type encrypt_with_rsa(char *message, char *encrypted_message, char *public_key)
{
    if (message == NULL || encrypted_message == NULL || public_key == NULL)
    {
        fprintf(stderr, "Error: message, encrypted_message and public_key must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t message_len = strlen(message);
    size_t encrypted_len = 0;

    // Read the public key from the string
    bio = BIO_new_mem_buf(public_key, -1);
    if (!bio)
    {
        fprintf(stderr, "Error creating BIO\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return CCRYPTO_ERROR_OPENSSL;
    }

    BIO_free(bio);

    // Create an RSA encryption context
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Error creating encryption context\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return CCRYPTO_ERROR_OPENSSL;
    }

    EVP_PKEY_free(pkey);

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        fprintf(stderr, "Error initializing encryption context\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Set the padding mode to PKCS#1 v1.5
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        fprintf(stderr, "Error setting padding mode\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Determine the maximum size of the encrypted message
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, (unsigned char *)message, message_len) <= 0)
    {
        fprintf(stderr, "Error determining encrypted message size\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Encrypt the message
    if (EVP_PKEY_encrypt(ctx, (unsigned char *)encrypted_message,
                         &encrypted_len, (unsigned char *)message,
                         message_len) <= 0)
    {
        fprintf(stderr, "Error encrypting message\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);

    return CCRYPTO_SUCCESS;
}