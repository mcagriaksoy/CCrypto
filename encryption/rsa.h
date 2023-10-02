// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

#ifndef CCRYPTO_RSA_H
#define CCRYPTO_RSA_H

#include "../common/types.h"

/**
 * @brief Encrypts a message using RSA encryption.
 *
 * @param message The message to encrypt.
 * @param encrypted_message The buffer to store the encrypted message.
 * @param public_key The public key to use for encryption.
 *
 * @return A ccrypto_error_type indicating the success or failure of the encryption.
 */
ccrypto_error_type encrypt_with_rsa(char *message, char *encrypted_message, char *public_key);

#endif // CCRYPTO_RSA_H
