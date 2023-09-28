CC = gcc

CFLAGS = -I -Wall -Wextra -O3
LIBS = -lssl -lcrypto -lcunit
SRCS = run_all_tests.c \
	   ../encryption/aes.c \
	   ../encryption/rsa.c \
	   ../encryption/des.c \
	   ../encryption/blowfish.c \
	   ../checksum/sha3.c \
	   ../checksum/md5.c \
	   ../checksum/crc.c \

test: run_all_tests.c
	@$(CC) $(CFLAGS) -o run_all_tests $(SRCS) $(LIBS)

clean:
	@$(RM) test