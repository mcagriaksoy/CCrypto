CC = gcc

CFLAGS = -I -Wall -Wextra -O3 -DOPENSSL_SUPPRESS_DEPRECATED
LIBS = -lssl -lcrypto -lcunit
SRCS = run_all_tests.c \
	   ../encryption/aes.c \
	   ../encryption/rsa.c \
	   ../encryption/des.c \
	   ../encryption/blowfish.c \
	   ../encryption/ecc.c \
	   ../decryption/aes.c \
	   ../decryption/des.c \
	   ../decryption/blowfish.c \
	   ../decryption/ecc.c \
	   ../checksum/sha3.c \
	   ../checksum/md5.c \
	   ../checksum/crc.c \

test: run_all_tests.c
	@$(CC) $(CFLAGS) -o run_all_tests $(SRCS) $(LIBS)

clean:
	@$(RM) test