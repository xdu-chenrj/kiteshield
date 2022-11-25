CFLAGS_COMMON = -Wall -std=gnu99 -I ..
CFLAGS = $(CFLAGS_COMMON) -O2

LDFLAGS = -Lbddisasm/bin/x64/Release

SRCS = $(wildcard *.c ../common/*.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
BIN_NAME = encryptor

.PHONY: all debug debug-antidebug output-dirs clean

debug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT -DNO_ANTIDEBUG
debug-antidebug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT

all: output-dirs $(OBJS)
	$(CC) $(OBJS) -o $(BIN_NAME) $(LDFLAGS)

debug: all
debug-antidebug: all

output-dirs:
	mkdir -p obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
