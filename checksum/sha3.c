// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "sha3.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

ccrypto_error_type str_to_sha3(uint8_t *str, size_t str_size, sha3_type algo_type, uint8_t *sha3_value, size_t *sha3_value_size)
{
    if (str == NULL || str_size == 0 || sha3_value == NULL || sha3_value_size == NULL)
    {
        printf("Error: str, str_size, sha3_value and sha3_value_size must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    uint32_t sha_length;
    EVP_MD *algorithm = NULL;
    switch (algo_type)
    {
    case SHA3_224:
        sha_length = SHA224_DIGEST_LENGTH;
        algorithm = EVP_sha3_224();
        break;
    case SHA3_256:
        sha_length = SHA256_DIGEST_LENGTH;
        algorithm = EVP_sha3_256();
        break;
    case SHA3_384:
        sha_length = SHA384_DIGEST_LENGTH;
        algorithm = EVP_sha3_384();
        break;
    case SHA3_512:
        sha_length = SHA512_DIGEST_LENGTH;
        algorithm = EVP_sha3_512();
        break;
    default:
        printf("Error: Invalid sha3 type.\n");
        free(algorithm);
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    // SHA3_Init
    uint8_t *sha_value = (uint8_t *)(OPENSSL_malloc(sha_length));
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL)
    {
        printf("Error: EVP_MD_CTX_new failed.\n");
        OPENSSL_free(sha_value);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // SHA_Init
    if (EVP_DigestInit_ex(context, algorithm, NULL) == 0)
    {
        printf("Error: EVP_DigestInit_ex failed.\n");
        OPENSSL_free(sha_value);
        EVP_MD_CTX_destroy(context);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // SHA_Update
    if (EVP_DigestUpdate(context, str, str_size) == 0)
    {
        printf("Error: EVP_DigestUpdate failed.\n");
        OPENSSL_free(sha_value);
        EVP_MD_CTX_destroy(context);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // SHA_Final
    if (EVP_DigestFinal_ex(context, sha_value, &sha_length) == 0)
    {
        printf("Error: EVP_DigestFinal_ex failed.\n");
        OPENSSL_free(sha_value);
        EVP_MD_CTX_destroy(context);
        return CCRYPTO_ERROR_OPENSSL;
    }

    EVP_MD_CTX_destroy(context);

    memcpy(sha3_value, sha_value, sha_length);
    *sha3_value_size = sha_length;
    OPENSSL_free(sha_value);

    return CCRYPTO_SUCCESS;
}