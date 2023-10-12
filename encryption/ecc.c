// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "ecc.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <string.h>

#define PUBLIC_KEY_SIZE 65

ccrypto_error_type ccrypto_ecc_encrypt(const uint8_t *public_key,
                                       const uint8_t *plain_text,
                                       const size_t data_length,
                                       uint8_t *encrypted_data,
                                       size_t *encrypted_data_length)
{
    if (public_key == NULL || plain_text == NULL || encrypted_data == NULL || encrypted_data_length == NULL)
    {
        printf("Error: public_key, plain_text, encrypted_data and encrypted_data_length must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }
    return CCRYPTO_SUCCESS;
}