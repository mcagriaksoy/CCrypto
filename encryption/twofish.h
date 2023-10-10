// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_TWOFISH_H
#define CCRYPTO_TWOFISH_H

#include "../common/types.h"
#include <stddef.h>
#include <stdint.h>

ccrypto_error_type ccrypto_twofish_encrypt(const uint8_t *key,
                                           size_t key_size,
                                           const uint8_t *data,
                                           uint8_t *output);

#endif // CCRYPTO_TWOFISH_H