/**
 * @file rsa.h
 * @author Mehmet Cagri Aksoy
 * @brief This file contains the definition of rsa encryption functions used in CCrypto library.
 * @see https://github.com/mcagriaksoy/CCrypto
 *
 */

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
