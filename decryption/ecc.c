// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "ecc.h"
#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

ccrypto_error_type ccrypto_ecc_decrypt(const uint8_t *private_key,
                                       const uint8_t *data,
                                       const size_t data_length,
                                       uint8_t *decrypted_data,
                                       size_t *decrypted_data_length)
{
    if (private_key == NULL || data == NULL || data_length == 0 ||
        decrypted_data == NULL || decrypted_data_length == NULL)
    {
        printf("ccrypto_ecc_decrypt: Invalid parameter(s).\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the ECC context
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL)
    {
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Set the private key
    EC_POINT *ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (ec_point == NULL)
    {
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }

    if (EC_POINT_oct2point(EC_KEY_get0_group(ec_key), ec_point, private_key, 32, NULL) != 1)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }

    if (EC_KEY_set_private_key(ec_key, ec_point) != 1)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Initialize the decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, private_key, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // Decrypt the data
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted_data, &len, data, data_length) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }
    *decrypted_data_length = len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return CCRYPTO_ERROR_OPENSSL;
    }
    *decrypted_data_length += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    EC_POINT_free(ec_point);
    EC_KEY_free(ec_key);

    return CCRYPTO_SUCCESS;
}