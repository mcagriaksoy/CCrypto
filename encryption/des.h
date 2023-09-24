// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DES_H
#define CCRYPTO_DES_H

/**
 * @brief Encrypts the given data using the DES algorithm.
 *
 * @param key The encryption key.
 * @param data The data to be encrypted.
 * @param encrypted The encrypted data.
 */
void des_encrypt(unsigned char *key, unsigned char *data, unsigned char *encrypted);

#endif //CCRYPTO_DES_H