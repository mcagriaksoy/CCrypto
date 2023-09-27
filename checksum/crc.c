// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "crc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// CRC polynomials
#define CRC8_POLYNOMIAL 0x07
#define CRC16_POLYNOMIAL 0x8005
#define CRC32_POLYNOMIAL 0x04C11DB7

ccrypto_error_type str_to_crc(uint8_t *str, size_t str_size, crc_type_t crc_type, uint8_t *crc_value, size_t *crc_value_size)
{
    if (str == NULL || str_size == 0 || crc_value == NULL || crc_value_size == NULL)
    {
        printf("Error: str, str_size, crc_value and crc_value_size must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    uint8_t crc_size;
    uint32_t crc_polynomial;
    switch(crc_type)
    {
        case CRC8:
            crc_size = CRC8;
            crc_polynomial = CRC8_POLYNOMIAL;
            break;
        case CRC16:
            crc_size = CRC16;
            crc_polynomial = CRC16_POLYNOMIAL;
            break;
        case CRC32:
            crc_size = CRC32;
            crc_polynomial = CRC32_POLYNOMIAL;
            break;
        default:
            printf("Error: Invalid crc type.\n");
            return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    uint32_t crc = 0;
    for (size_t i = 0; i < str_size; i++)
    {
        crc ^= str[i];
        for (size_t j = 0; j < crc_size; j++)
        {
            if (crc & 0x80) // 0x80 = 0b10000000
            {
                crc = (crc << 1) ^ crc_polynomial;
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    memcpy(crc_value, &crc, crc_size/CRC8);
    *crc_value_size = crc_size/CRC8;

    return CCRYPTO_SUCCESS;
}
