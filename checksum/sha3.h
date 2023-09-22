// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_SHA3_H
#define CCRYPTO_SHA3_H

#include <stdlib.h>
#include <stdint.h>

// sha3 types.
typedef enum{
    SHA3_224 = 224,
    SHA3_256 = 256,
    SHA3_384 = 384,
    SHA3_512 = 512
} sha3_type;

/*
The function str_to_sha3 is a C function that calculates the SHA3 hash of a given string and stores
it in a buffer. The SHA3 hash is a 224-bit, 256-bit, 384-bit, or 512-bit value that is commonly
represented as a 56-character, 64-character, 96-character, or 128-character hexadecimal number.
The SHA3 algorithm is a cryptographic hash function that produces a fixed-length output from a
variable-length input.
*/
void str_to_sha3(uint8_t *str, size_t str_size, sha3_type algo_type, uint8_t *sha3_value, size_t *sha3_value_size);

#endif // CCRYPTO_SHA3_H