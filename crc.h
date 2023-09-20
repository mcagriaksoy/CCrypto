// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_CRC_H
#define CCRYPTO_CRC_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CRC8 = 8,
    CRC16 = 16,
    CRC32 = 32
} crc_type_t;

// CRC-8 (CRC-8-ATM) is a 8-bit CRC checksum algorithm.
void str_to_crc(uint8_t *str, size_t str_size, crc_type_t crc_type, uint8_t *crc_value, size_t *crc_value_size);

#endif  // CCrypto_crc_h