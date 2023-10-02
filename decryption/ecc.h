// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_DECRYPT_ECC_H
#define CCRYPTO_DECRYPT_ECC_H

#include <string.h>

#include "../common/types.h"

/**
 * @brief Decrypts data using elliptic curve cryptography (ECC).
 *
 * This function decrypts the given data using the provided private_key key and the
 * AES-256-CBC encryption algorithm. The decrypted data is stored in the output
 * buffer, and the length of the decrypted data is stored in the output length
 * variable.
 *
 * @param private_key The private_key key to use for decryption.
 * @param data The data to decrypt.
 * @param data_length The length of the data to decrypt.
 * @param decrypted_data The output buffer to store the decrypted data.
 * @param decrypted_data_length A pointer to a variable to store the length of the decrypted data.
 *
 * @return A ccrypto_error_type indicating the success or failure of the decryption.
 *         If the decryption was successful, CCRYPTO_SUCCESS is returned.
 *         If an error occurred during decryption, an appropriate error code is returned.
 */
ccrypto_error_type ccrypto_ecc_decrypt(const uint8_t *private_key, const uint8_t *data, const size_t data_length, uint8_t *decrypted_data, size_t *decrypted_data_length);

#endif //CCRYPTO_DECRYPT_ECC_H