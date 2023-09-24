CC = gcc

CFLAGS = -I -Wall -Wextra -O3
LIBS = -lssl -lcrypto
SRCS = md5.c sha3.c crc.c

md5:
	@$(CC) $(CFLAGS) -o test $(SRCS) $(LIBS)

clean:
	@$(RM) md5