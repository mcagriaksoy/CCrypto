# CCrypto API
<a href="https://github.com/mcagriaksoy/CCrypto" title="Go to GitHub repo"><img src="https://img.shields.io/static/v1?label=mcagriaksoy&message=CCrypto&color=blue&logo=github" alt="mcagriaksoy - CCrypto"></a>
<a href="https://github.com/mcagriaksoy/CCrypto"><img src="https://img.shields.io/github/stars/mcagriaksoy/CCrypto?style=social" alt="stars - CCrypto"></a>
<a href="https://github.com/mcagriaksoy/CCrypto"><img src="https://img.shields.io/github/forks/mcagriaksoy/CCrypto?style=social" alt="forks - CCrypto"></a>
<a href="https://github.com/mcagriaksoy/CCrypto/releases/"><img src="https://img.shields.io/github/tag/mcagriaksoy/CCrypto?include_prereleases=&sort=semver&color=blue" alt="GitHub tag"></a>
<a href="#license"><img src="https://img.shields.io/badge/License-MIT-blue" alt="License"></a>
<a href="https://github.com/mcagriaksoy/CCrypto/issues"><img src="https://img.shields.io/github/issues/mcagriaksoy/CCrypto" alt="issues - CCrypto"></a>
<div align="center">
<a href="https://github.com/mcagriaksoy/CCrypto/generate"><img src="https://img.shields.io/badge/Generate-Use_this_template-2ea44f?style=for-the-badge" alt="Use this template"></a>
<a href="https://mcagriaksoy.github.io/CCrypto/"><img src="https://img.shields.io/badge/View_site-GH_Pages-2ea44f?style=for-the-badge" alt="View site - GH Pages"></a>

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

</div>
<h2>Documentation</h2>
<div align="center">
<a href="/docs/" title="Go to project documentation"><img src="https://img.shields.io/badge/view-Documentation-blue?style=for-the-badge" alt="view - Documentation"></a>

</div>
<h2>License</h2>
Released under <a href="/LICENSE">MIT</a> by <a href="https://github.com/mcagriaksoy">@mcagriaksoy</a>.

Under /test folder when you trigger the make, you will see the object named `run_all_tests`

`./run_all_tests` with this command you trigger the all tests.


