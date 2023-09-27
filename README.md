# CCrypto API
## Description
C Crypto API that create layer between user and the complex openssl functions. My API aims to create user friendly functions for some crypto functions.

## Modules
### Checksum
ccrypto api has checksum support. It supports:

1- CRC8, CRC16, CRC32

2- md5

3- SHA3 with 224, 256, 384, 512 bit support

### Encryption
ccrypto api has encryption support. It supports:

1- AES with CBC and ECB mode.

2- RSA

3- (Triple) 3DES

## Dependencies
- OpenSSL
- CUnit

## How to use
As mentioned above, the Ccrypto API uses openssl base. So you need openssl installed in your system.

In ubuntu or any debian distro`s you can type following to install openssl:

` sudo apt-get install libssl-dev `

Also you need to ensure that gcc is installed and supported in your system:

` gcc --version ` 

If there is no version displayed you need to install via following line:

` sudo apt install build-essential gdb `

For test purposes ccrypto uses CUnit test framework. You need to install it as well.

` sudo apt-get install libcunit1 libcunit1-doc libcunit1-dev `

Afterwards you need to type only:

` make `

Under /test folder when you trigger the make, you will see the object named `run_all_tests`

`./run_all_tests` with this command you trigger the all tests.


