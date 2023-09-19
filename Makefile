CC = gcc

CFLAGS = -I -Wall -Wextra -O3
LIBS = -lssl -lcrypto
SRCS = md5.c main.c sha3.c

md5: md5.c main.c
	@$(CC) $(CFLAGS) -o test $(SRCS) $(LIBS)

clean:
	@$(RM) md5