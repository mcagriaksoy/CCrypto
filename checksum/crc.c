// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#include "crc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Calculates the CRC-8 hash of a string.
 *
 * This function calculates the CRC-8 hash of the given string. The resulting hash value
 * is stored in the output buffer.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param crc The output buffer to store the hash value. The buffer must be at least 1 byte long.
 *
 * @return None.
 */
void crc_8_calculation(uint8_t *str, size_t str_size, uint8_t *crc)
{
    if (str == NULL || str_size == 0 || crc == NULL)
    {
        printf("Error: str, str_size and crc must not be NULL\n");
        return;
    }

    const uint8_t polynomial = 0x07;

    for (size_t i = 0; i < str_size; i++)
    {
        *crc ^= str[i];
        for (size_t j = 0; j < (size_t)CRC8; j++)
        {
            if (*crc & 0x80) // 0x80 = 0b10000000
            {
                *crc = (*crc << 1) ^ polynomial;
            }
            else
            {
                *crc <<= 1;
            }
        }
    }
}

/**
 * @brief Calculates the CRC-16-CCITT hash of a string.
 * @note CRC-16-CCITT (poly 0x1021) is the most common CRC-16 and most well-proven in use.
 *       So that this algorithm is selected as default.
 *
 * This function calculates the CRC-16 hash of the given string. The resulting hash value
 * is stored in the output buffer.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param crc The output buffer to store the hash value. The buffer must be at least 2 bytes long.
 *
 * @return None.
 */
void crc_16_calculation(uint8_t *str, size_t str_size, uint8_t *crc)
{
    uint8_t x;
    uint16_t crc_temp = 0xFFFF;
    size_t length = str_size;

    while (length--)
    {
        x = crc_temp >> 8 ^ *str++;
        x ^= x >> 4;
        crc_temp = (crc_temp << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x << 5)) ^ ((unsigned short)x);
    }

    ccrypto_memcpy(crc, &crc_temp, 2);
}

/**
 * @brief Calculates the CRC-32/JAMCRC hash of a string.
 *
 * This function calculates the CRC-32/JAMCRC hash of the given string. The resulting hash value
 * is stored in the output buffer.
 *
 * @param str The string to hash.
 * @param str_size The length of the string to hash.
 * @param crc The output buffer to store the hash value. The buffer must be at least 4 bytes long.
 *
 * @return None.
 */
void crc_32_calculation(uint8_t *str, size_t str_size, uint8_t *crc)
{
    uint32_t crc_temp = 0xFFFFFFFF;
    size_t length = str_size;

    while (length--)
    {
        crc_temp ^= *str++;
        for (size_t i = 0; i < 8; i++)
        {
            crc_temp = (crc_temp >> 1) ^ (0xEDB88320 & (-(crc_temp & 1)));
        }
    }

    ccrypto_memcpy(crc, &crc_temp, 4);
}

ccrypto_error_type str_to_crc(uint8_t *str, size_t str_size, crc_type_t crc_type,
                              uint8_t *crc_value, size_t *crc_value_size)
{
    if (str == NULL || str_size == 0 || crc_value == NULL || crc_value_size == NULL)
    {
        printf("Error: str, str_size, crc_value and crc_value_size must not be NULL\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    switch (crc_type)
    {
    case CRC8:
        crc_8_calculation(str, str_size, crc_value);
        break;
    case CRC16:
        crc_16_calculation(str, str_size, crc_value);
        break;
    case CRC32:
        crc_32_calculation(str, str_size, crc_value);
        break;
    default:
        printf("Error: Invalid crc type.\n");
        return CCRYPTO_ERROR_INVALID_ARGUMENT;
    }

    *crc_value_size = crc_type / CRC8;
    return CCRYPTO_SUCCESS;
}
