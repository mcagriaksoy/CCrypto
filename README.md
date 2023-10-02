CCrypto is an API that create layer between user and the complex openssl functions. It aims to create user friendly and easy to use functions for cryptography functions.

![Screenshot 2023-09-25 111803](https://github.com/mcagriaksoy/CCrypto/assets/20202577/2640d0d5-5fcd-4722-9de3-0df76f4123c9)

<a href="https://github.com/mcagriaksoy/CCrypto" title="Go to GitHub repo"><img src="https://img.shields.io/static/v1?label=mcagriaksoy&message=CCrypto&color=blue&logo=github" alt="mcagriaksoy - CCrypto"></a>
[![Pipeline - Passing](https://img.shields.io/badge/Pipeline-Passing-2ea44f)](https://)
<a href="https://github.com/mcagriaksoy/CCrypto/releases/"><img src="https://img.shields.io/github/tag/mcagriaksoy/CCrypto?include_prereleases=&sort=semver&color=blue" alt="GitHub tag"></a>
<a href="#license"><img src="https://img.shields.io/badge/License-MIT-blue" alt="License"></a>
<a href="https://github.com/mcagriaksoy/CCrypto/issues"><img src="https://img.shields.io/github/issues/mcagriaksoy/CCrypto" alt="issues - CCrypto"></a>
[![Hosted with GH Pages](https://img.shields.io/badge/Hosted_with-GitHub_Pages-blue?logo=github&logoColor=white)](https://pages.github.com/ "Go to GitHub Pages homepage")
[![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/ "Go to Linux homepage")
[![OS - Windows](https://img.shields.io/badge/OS-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/ "Go to Microsoft homepage")

<a href="https://github.com/mcagriaksoy/CCrypto"><img src="https://img.shields.io/github/stars/mcagriaksoy/CCrypto?style=social" alt="stars - CCrypto"></a>
<a href="https://github.com/mcagriaksoy/CCrypto"><img src="https://img.shields.io/github/forks/mcagriaksoy/CCrypto?style=social" alt="forks - CCrypto"></a>

## Description

## Modules
### Checksum
ccrypto api has checksum support. It supports:

1- CRCs
  - CRC8
  - CRC16
  - CRC32

2- MD5

3- SHA3
  - 224 bit
  - 256 bit
  - 384 bit
  - 512 bit

### Encryption / Decryption
ccrypto api has encryption and decryption support. It supports:

1- AES
  - CBC mode
  - ECB mode

2- RSA

3- (Triple) 3DES

4- Blowfish

## Dependencies
[![OpenSSL - >= 3.0](https://img.shields.io/badge/OpenSSL->=_3.0-2ea44f)](https://www.openssl.org/source/)
[![CUnit - >= 2.0](https://img.shields.io/badge/CUnit->=_2.0-2ea44f)](https://cunit.sourceforge.net)

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


</div>
<h2>Documentation</h2>
<div align="center">
<a href="/docs/" title="Go to project documentation"><img src="https://img.shields.io/badge/view-Documentation-blue?style=for-the-badge" alt="view - Documentation"></a>

</div>
<h2>License</h2>
Released under <a href="/LICENSE">MIT</a> by <a href="https://github.com/mcagriaksoy">@mcagriaksoy</a>.
