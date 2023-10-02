// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_ECC_H
#define CCRYPTO_ECC_H

#include <string.h>

#include "../common/types.h"

/**
 * @brief Encrypts data using elliptic curve cryptography (ECC).
 *
 * This function encrypts the given data using the provided public key and the
 * AES-256-CBC encryption algorithm. The encrypted data is stored in the output
 * buffer, and the length of the encrypted data is stored in the output length
 * variable.
 *
 * @param public_key The public key to use for encryption.
 * @param plain_text The data to encrypt.
 * @param data_length The length of the data to encrypt.
 * @param encrypted_data The output buffer to store the encrypted data.
 * @param encrypted_data_length A pointer to a variable to store the length of the encrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the encryption.
 *         If the encryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during encryption, an appropriate error code is returned.
 */
ccrypto_error_type ccrypto_ecc_encrypt(const uint8_t *public_key, const uint8_t *plain_text, const size_t data_length, uint8_t *encrypted_data, size_t *encrypted_data_length);

#endif // CCRYPTO_ECC_H