// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "../include/checksum/md5.h"

#include <stdlib.h>

#include <openssl/evp.h>

static void str_to_md5(uint8_t *str, size_t str_size, uint8_t *md5_value, size_t *md5_value_size)
{
    EVP_MD_CTX *mdctx;
    unsigned char *md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    
    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // MD5_Update
    EVP_DigestUpdate(mdctx, str, str_size);

    // MD5_Final
    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);

    memcpy(md5_value, md5_digest, md5_digest_len);
    *md5_value_size = md5_digest_len;
    OPENSSL_free(md5_digest);
    EVP_MD_CTX_free(mdctx);
}
