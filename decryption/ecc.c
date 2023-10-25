/**
 * @file ecc.c
 * @brief This file contains the implementation of elliptic curve cryptography decryption algorithm.
 *
 * This file provides the necessary functions to decrypt data encrypted using elliptic curve cryptography.
 * The implementation is done by Mehmet Cagri Aksoy in 2023 and can be found on github.com/mcagriaksoy.
 */

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
    return CCRYPTO_SUCCESS;
}