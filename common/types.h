// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_TYPES_H
#define CCRYPTO_TYPES_H

#include <stdint.h>

typedef unsigned int ccrypto_error_type;

#define CCRYPTO_SUCCESS 0
#define CCRYPTO_ERROR 1

#define CCRYPTO_ERROR_INVALID_KEY 2
#define CCRYPTO_ERROR_INVALID_MESSAGE 3
#define CCRYPTO_ERROR_INVALID_ENCRYPTED_MESSAGE 4

#define CCRYPTO_ERROR_INVALID_SIGNATURE 5
#define CCRYPTO_ERROR_INVALID_SIGNATURE_LENGTH 6

#define CCRYPTO_ERROR_INVALID_HASH 7
#define CCRYPTO_ERROR_INVALID_HASH_LENGTH 8

#define CCRYPTO_ERROR_INVALID_PUBLIC_KEY 9
#define CCRYPTO_ERROR_INVALID_PRIVATE_KEY 10

#define CCRYPTO_ERROR_INVALID_PUBLIC_KEY_LENGTH 11
#define CCRYPTO_ERROR_INVALID_PRIVATE_KEY_LENGTH 12

#define CCRYPTO_ERROR_INVALID_PUBLIC_KEY_FILE 13
#define CCRYPTO_ERROR_INVALID_PRIVATE_KEY_FILE 14

#define CCRYPTO_ERROR_INVALID_ARGUMENT 15
#define CCRYPTO_ERROR_OPENSSL 16

#ifdef _WIN32
#define ccrypto_memcpy(dest, destz, src, n) memcpy_s(dest, destz, src, n)
#else
#define ccrypto_memcpy(dest, src, n) memcpy(dest, src, n)
#endif

typedef enum
{
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
} ccrypto_aes_size_t;

typedef enum
{
    CRC8 = 8,
    CRC16 = 16,
    CRC32 = 32
} crc_type_t;

#endif // CCRYPTO_TYPES_H
