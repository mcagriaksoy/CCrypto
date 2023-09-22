CC = gcc

CFLAGS = -I -Wall -Wextra -O3
LIBS = -lssl -lcrypto
SRCS = aes.c main.c
aes: aes.c main.c
	@$(CC) $(CFLAGS) -o test $(SRCS) $(LIBS)

clean:
	@$(RM) aes