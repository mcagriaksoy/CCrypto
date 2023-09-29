// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DECRYPT_DES_H
#define CCRYPTO_DECRYPT_DES_H

#include "../common/types.h"
#include <stddef.h>

ccrypto_error_type des3_decrypt_with_ecb(
        const uint8_t *key,     
        const uint8_t *input,
        size_t input_length,
        uint8_t *output,
        size_t *output_length
);

ccrypto_error_type des3_decrypt_with_cbc(
        const uint8_t *key,
        const uint8_t *iv,       
        const uint8_t *input,
        size_t input_length,
        uint8_t *output,
        size_t *output_length
);

#endif //CCRYPTO_DECRYPT_DES_H