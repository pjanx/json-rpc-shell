SHELL = /bin/sh
CC = clang
# -Wunused-function is pretty annoying here, as everything is static
CFLAGS = -std=c99 -Wall -Wextra -Wno-unused-function -ggdb
# -lpthread is only there for debugging (gdb & errno)
LDFLAGS = `pkg-config --libs libcurl jansson` -lpthread -lreadline

.PHONY: all clean
.SUFFIXES:

targets = json-rpc-shell

all: $(targets)

clean:
	rm -f $(targets)

json-rpc-shell: json-rpc-shell.c
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)
