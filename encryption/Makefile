CC = gcc

CFLAGS = -I -Wall -Wextra -O3
LIBS = -lssl -lcrypto
SRCS = aes.c rsa.c
encrypt: aes.c rsa.c
	@$(CC) $(CFLAGS) -o encrypt $(SRCS) $(LIBS)

clean:
	@$(RM) encrypt