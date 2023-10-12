// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "md5.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

ccrypto_error_type str_to_md5(const uint8_t *plaintext,
                              size_t plaintext_size,
                              uint8_t *md5_value,
                              size_t *md5_value_size)
{
    if (plaintext == NULL || plaintext_size == 0 || md5_value == NULL || md5_value_size == NULL)
    {
        printf("Error: str, md5_value and md5_value_size must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    EVP_MD_CTX *mdctx;
    unsigned char *md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());

    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) == 0)
    {
        EVP_MD_CTX_free(mdctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // MD5_Update
    if (EVP_DigestUpdate(mdctx, plaintext, plaintext_size) == 0)
    {
        EVP_MD_CTX_free(mdctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    // MD5_Final
    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    if (EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len) == 0)
    {
        OPENSSL_free(md5_digest);
        EVP_MD_CTX_free(mdctx);
        return CCRYPTO_ERROR_OPENSSL;
    }

    ccrypto_memcpy(md5_value, md5_digest, md5_digest_len);
    *md5_value_size = md5_digest_len;
    OPENSSL_free(md5_digest);
    EVP_MD_CTX_free(mdctx);

    return CCRYPTO_SUCCESS;
}