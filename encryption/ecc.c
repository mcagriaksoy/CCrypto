// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "ecc.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

ccrypto_error_type ccrypto_ecc_encrypt(const uint8_t *public_key, const uint8_t *data, const size_t data_length, uint8_t *encrypted_data, size_t *encrypted_data_length)
{
    if(public_key == NULL || data == NULL || encrypted_data == NULL || encrypted_data_length == NULL)
    {
        printf("Error: public_key, data, encrypted_data and encrypted_data_length must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();

    // Create an EC_KEY object from the public key
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        return CCRYPTO_ERROR_INVALID_PUBLIC_KEY;
    }
    const uint8_t *public_key_ptr = public_key;
    EC_POINT *ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (EC_POINT_oct2point(EC_KEY_get0_group(ec_key), ec_point, public_key_ptr, EC_KEY_get0_public_key(ec_key), NULL) != 1) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        printf("Error: EC_POINT_oct2point failed\n");
        return CCRYPTO_ERROR_INVALID_PUBLIC_KEY;
    }
    EC_KEY_set_public_key(ec_key, ec_point);

    // Generate a shared secret using ECDH
    uint8_t shared_secret[EVP_MAX_MD_SIZE];
    size_t shared_secret_length;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        printf("Error: EVP_PKEY_derive_init failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    if (EVP_PKEY_derive_set_peer(pctx, pkey) <= 0) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        printf("Error: EVP_PKEY_derive_set_peer failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    if (EVP_PKEY_derive(pctx, shared_secret, &shared_secret_length) <= 0) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        printf("Error: EVP_PKEY_derive failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    // Encrypt the data using the shared secret as the key
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, shared_secret, shared_secret + 16) != 1) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_CIPHER_CTX_free(ctx);
        printf("Error: EVP_EncryptInit_ex failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    int outlen;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &outlen, data, data_length) != 1) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_CIPHER_CTX_free(ctx);
        printf("Error: EVP_EncryptUpdate failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + outlen, &final_len) != 1) {
        EC_KEY_free(ec_key);
        EC_POINT_free(ec_point);
        EVP_CIPHER_CTX_free(ctx);
        printf("Error: EVP_EncryptFinal_ex failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }
    *encrypted_data_length = outlen + final_len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    EC_KEY_free(ec_key);
    EC_POINT_free(ec_point);
    
    return CCRYPTO_SUCCESS;
}