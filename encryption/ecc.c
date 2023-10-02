// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "ecc.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <string.h>

ccrypto_error_type ccrypto_ecc_encrypt(const uint8_t *public_key, const uint8_t *plain_text,
                                       const size_t data_length, uint8_t *encrypted_data,
                                       size_t *encrypted_data_length)
{
    if (public_key == NULL || plain_text == NULL || encrypted_data == NULL || encrypted_data_length == NULL)
    {
        printf("Error: public_key, plain_text, encrypted_data and encrypted_data_length must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the ECC context
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL)
    {
        printf("Error: EC_KEY_new_by_curve_name failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Set the public key
    EC_POINT *ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (ec_point == NULL)
    {
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }

    if (EC_POINT_oct2point(EC_KEY_get0_group(ec_key), ec_point, public_key, 65, NULL) != 1)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EC_POINT_oct2point failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    if (EC_KEY_set_public_key(ec_key, ec_point) != 1)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EC_KEY_set_public_key failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Initialize the encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EVP_CIPHER_CTX_new failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, public_key, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EVP_EncryptInit_ex failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Encrypt the plain_text
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len, plain_text, data_length) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EVP_EncryptUpdate failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    *encrypted_data_length = len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        printf("Error: EVP_EncryptFinal_ex failed\n");
        return CCRYPTO_ERROR_OPENSSL;
    }

    *encrypted_data_length += len;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    EC_POINT_free(ec_point);
    EC_KEY_free(ec_key);

    return CCRYPTO_SUCCESS;
}