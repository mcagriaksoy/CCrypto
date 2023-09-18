// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_MD5_H
#define CCRYPTO_MD5_H

#include <stdlib.h>
#include <stdint.h>
/*
The function str_to_md5 is a C function that calculates the MD5 hash of a given string and stores
it in a buffer. The MD5 hash is a 128-bit value that is commonly represented as a 32-character
hexadecimal number1.The MD5 algorithm is a widely used cryptographic hash function that produces
a fixed-length output from a variable-length input2.

The function has four parameters:

uint8_t *str: This is a pointer to the string whose MD5 hash is to be calculated. 
It should be a null-terminated string of 8-bit unsigned characters.

size_t str_size: This is the size of the string in bytes, excluding the null terminator. 
It should be a positive integer value.

uint8_t *md5_value: This is a pointer to the buffer where the MD5 hash value will be stored. 
It should have enough space to store 16 bytes of data
*/
static void str_to_md5(uint8_t *str, size_t str_size, uint8_t *md5_value, size_t *md5_value_size);

#endif // CCRYPTO_MD5_H