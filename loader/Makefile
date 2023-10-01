# CFLAGS_COMMON = -Wall -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I ..
CFLAGS_COMMON = -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I .. -I../cyclone_cipher -I../cyclone_cipher/common -I../compression/lzma -I../compression/lzo -I../compression/ucl \
				-I../compression/ucl/include -I../compression/ucl/src
LDFLAGS = -no-pie 
LIB = -L../cyclone_cipher -lcrypto

CFLAGS = $(CFLAGS_COMMON)

SRCS = $(wildcard *.[c,S] ../common/*.c ../compression/zstd/zstddeclib.c ../compression/lzma/*.c ../compression/lzo/*.c ../compression/ucl/src/*.c)
OBJS_RT = $(addprefix out/rt/, $(addsuffix .o, $(basename $(notdir $(SRCS:.c=.o)))))
OBJS_NO_RT = $(addprefix out/no_rt/, $(addsuffix .o, $(basename $(notdir $(SRCS:.c=.o)))))

OBFUSCATED_STRINGS_HEADER = include/obfuscated_strings.h

.PHONY: all output-dirs debug debug-antidebug clean tests

debug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT -DNO_ANTIDEBUG
debug-antidebug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT

# all: output-dirs $(OBFUSCATED_STRINGS_HEADER) out/loader_header_rt.h out/loader_header_no_rt.h tests
all: output-dirs $(OBFUSCATED_STRINGS_HEADER) out/loader_header_rt.h out/loader_header_no_rt.h
debug: all
debug-antidebug: all

tests:
	$(MAKE) -C test clean
	$(MAKE) -C test

out/loader_header_rt.h: $(OBJS_RT)
	$(LD) $(LDFLAGS) $(OBJS_RT) $(LIB) -T link.lds -o out/rt/loader-elf
	objcopy -O binary out/rt/loader-elf out/rt/loader.bin
	cat out/rt/loader.bin | python3 bin_to_header.py GENERATED_LOADER_RT > out/generated_loader_rt.h

out/loader_header_no_rt.h: $(OBJS_NO_RT)
	$(LD) $(LDFLAGS) $(OBJS_NO_RT) $(LIB) -T link.lds -o out/no_rt/loader-elf
	objcopy -O binary out/no_rt/loader-elf out/no_rt/loader.bin
	cat out/no_rt/loader.bin | python3 bin_to_header.py GENERATED_LOADER_NO_RT > out/generated_loader_no_rt.h

$(OBFUSCATED_STRINGS_HEADER):
	python3 string_obfuscation.py > $(OBFUSCATED_STRINGS_HEADER)

out/rt/%.o: %.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: ../common/%.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: ../compression/zstd/%.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: ../compression/lzma/%.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: ../compression/lzo/%.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: ../compression/ucl/src/%.c
	$(CC) -DUSE_RUNTIME $(CFLAGS) $< -o $@

out/rt/%.o: %.S
	$(CC) -DUSE_RUNTIME -c $< -o $@

out/no_rt/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

out/no_rt/%.o: ../common/%.c
	$(CC) $(CFLAGS) $< -o $@

out/no_rt/%.o: ../compression/zstd/%.c
	$(CC) $(CFLAGS) $< -o $@

out/no_rt/%.o: ../compression/lzma/%.c
	$(CC) $(CFLAGS) $< -o $@

out/no_rt/%.o: ../compression/lzo/%.c
	$(CC) $(CFLAGS) $< -o $@

out/no_rt/%.o: ../compression/ucl/src/%.c
	$(CC) $(CFLAGS) $< -o $@

out/no_rt/%.o: %.S
	$(CC) -c $< -o $@

output-dirs:
	mkdir -p out/rt
	mkdir -p out/no_rt

clean:
	$(MAKE) clean -C test
	rm -rf out/
	rm -f $(OBFUSCATED_STRINGS_HEADER)
