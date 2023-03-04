#include <stdio.h>
#include <time.h>
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

//#include "bddisasm.h"

#include "common/include/rc4.h"
#include "common/include/obfuscation.h"
#include "common/include/defs.h"
#include "packer/include/elfutils.h"

#include "loader/out/generated_loader_rt.h"
#include "loader/out/generated_loader_no_rt.h"

//串口通信

#include <strings.h>
#include <termios.h>
#include <malloc.h>

typedef struct termios termios_t;
typedef struct serial_data {
    unsigned char databuf[132];//发送/接受数据
    int serfd;//串口文件描述符
} ser_Data;
char key[128];

/* Convenience macro for error checking libc calls */
#define CK_NEQ_PERROR(stmt, err)                                               \
  do {                                                                         \
    if ((stmt) == err) {                                                       \
      perror(#stmt);                                                           \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define STRINGIFY_KEY(key)                                                    \
  ({ char buf[(sizeof(key.bytes) * 2) + 1];                                   \
     for (int i = 0; i < sizeof(key.bytes); i++) {                            \
       sprintf(&buf[i * 2], "%02hhx", key.bytes[i]);                          \
     };                                                                       \
     buf; })

static int log_verbose = 0;

/* Needs to be defined for bddisasm */
int nd_vsnprintf_s(char *buffer, size_t sizeOfBuffer, size_t count,
                   const char *format, va_list argptr) {
  return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}

/* Needs to be defined for bddisasm */
void *nd_memset(void *s, int c, size_t n) { return memset(s, c, n); }

static void err(char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  vfprintf(stderr, fmt, args);
  printf("\n");
}

static void info(char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);
  printf("\n");
}

static void verbose(char *fmt, ...) {
  if (!log_verbose)
    return;

  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);
  printf("\n");
}

static int read_input_elf(char *path, struct mapped_elf *elf) {
  void *elf_buf;
  size_t size;

  FILE *file;
  // 只读方式打开
  CK_NEQ_PERROR(file = fopen(path, "r"), NULL);
  // 将文件指针指向文件的末尾，偏移0字节
  CK_NEQ_PERROR(fseek(file, 0L, SEEK_END), -1);
  // 返回位置标识符的当前值(获取文件字节大小)
  CK_NEQ_PERROR(size = ftell(file), -1);
  // 申请空间
  CK_NEQ_PERROR(elf_buf = malloc(size), NULL);
  // 将文件指针指向文件开头，偏移0字节
  CK_NEQ_PERROR(fseek(file, 0L, SEEK_SET), -1);
  /**
   * size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
   * 从给定流 stream 读取数据到 ptr
   * ptr -- 这是指向带有最小尺寸 size*nmemb 字节的内存块的指针。
   * size -- 这是要读取的每个元素的大小，以字节为单位。
   * nmemb -- 这是元素的个数，每个元素的大小为 size 字节。
   * stream -- 这是指向 FILE 对象的指针，该 FILE 对象指定了一个输入流
   */
  CK_NEQ_PERROR(fread(elf_buf, size, 1, file), 0);
  // 关闭文件
  CK_NEQ_PERROR(fclose(file), EOF);

  parse_mapped_elf(elf_buf, size, elf);

  return 0;
}

static int produce_output_elf(FILE *output_file, struct mapped_elf *elf,
                              void *loader, size_t loader_size) {
  /* The entry address is located right after the struct rc4_key (used for
   * passing decryption key and other info to loader), which is the first
   * sizeof(struct rc4_key) bytes of the loader code (guaranteed by the linker
   * script) */
  Elf64_Addr entry_vaddr = LOADER_ADDR + sizeof(Elf64_Ehdr) +
                           (sizeof(Elf64_Phdr) * 2) + sizeof(struct rc4_key);
  Elf64_Ehdr ehdr;
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;
  memset(ehdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);

  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = EM_AARCH64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_entry = entry_vaddr;
  ehdr.e_phoff = sizeof(Elf64_Ehdr);
  ehdr.e_shoff = 0;
  ehdr.e_flags = 0;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = 2;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = 0;
  ehdr.e_shstrndx = SHN_UNDEF;

  CK_NEQ_PERROR(fwrite(&ehdr, sizeof(ehdr), 1, output_file), 0);

  /* Size of the first segment include the size of the ehdr and two phdrs */
  size_t hdrs_size = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  /* Program header for loader */
  Elf64_Phdr loader_phdr;
  loader_phdr.p_type = PT_LOAD;
  loader_phdr.p_offset = 0;
  loader_phdr.p_vaddr = LOADER_ADDR;
  loader_phdr.p_paddr = loader_phdr.p_vaddr;
  loader_phdr.p_filesz = loader_size + hdrs_size;
  loader_phdr.p_memsz = loader_size + hdrs_size;
  loader_phdr.p_flags = PF_R | PF_W | PF_X;
  loader_phdr.p_align = 0x200000;
  CK_NEQ_PERROR(fwrite(&loader_phdr, sizeof(loader_phdr), 1, output_file), 0);

  /* Program header for packed application */
  int app_offset = ftell(output_file) + sizeof(Elf64_Phdr) + loader_size;
  Elf64_Phdr app_phdr;
  app_phdr.p_type = PT_LOAD;
  app_phdr.p_offset = app_offset;
  app_phdr.p_vaddr = PACKED_BIN_ADDR + app_offset; /* Keep vaddr aligned */
  app_phdr.p_paddr = app_phdr.p_vaddr;
  app_phdr.p_filesz = elf->size;
  app_phdr.p_memsz = elf->size;
  app_phdr.p_flags = PF_R | PF_W;
  app_phdr.p_align = 0x200000;
  CK_NEQ_PERROR(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0);

  /* Loader code/data */
  CK_NEQ_PERROR(fwrite(loader, loader_size, 1, output_file), 0);

  /* Packed application contents */
//  CK_NEQ_PERROR(fwrite(elf->start, elf->size, 1, output_file), 0);
  void *add = malloc(elf->size);
  CK_NEQ_PERROR(fwrite(add, elf->size, 1, output_file), 0);

  return 0;
}

int convert_str_to_dec(char* str, int start, int end) {
  int res = 0;
  for(int i = start; i < end; i++) {
    res = res * 2 + (str[i] - '0');
  }
  return res;
}
static int get_random_bytes(void *buf, size_t len) {
    FILE *f;
    CK_NEQ_PERROR(f = fopen("/dev/urandom", "r"), NULL);
    CK_NEQ_PERROR(fread(buf, len, 1, f), 0);
    CK_NEQ_PERROR(fclose(f), EOF);
    return 0;
}

static void encrypt_memory_range(struct rc4_key *key, void *start, size_t len) {
  struct rc4_state rc4;
  rc4_init(&rc4, key->bytes, sizeof(key->bytes));

  uint8_t *curr = start;
  for (size_t i = 0; i < len; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }
}

static uint64_t get_base_addr(Elf64_Ehdr *ehdr) {
  /* Return the base address that the binary is to be mapped in at runtime. If
   * statically linked, use absolute addresses (ie. base address = 0).
   * Otherwise, everything is relative to DYN_PROG_BASE_ADDR. */
  return ehdr->e_type == ET_EXEC ? 0ULL : DYN_PROG_BASE_ADDR;
}

/* Determines if the given jmp instruction requires replacement by an int3 and
 * thus a trap into the runtime at program execution time. JMPs that do leave
 * or have the potential to leave their containing function require
 * instrumentation as otherwise program control would could be handed to
 * encrypted code.
 *
 * While not normally generated by C compilers for average C code, binaries can
 * and do have these kinds of jmps. setjmp/longjmp is one example. glibc
 * additionally contains several of these jumps as a result of handwritten asm
 * or other nonstandard internal constructs.
 */
// static int is_instrumentable_jmp(
//     INSTRUX *ix,
//     uint64_t fcn_start,
//     size_t fcn_size,
//     uint64_t ix_addr)
//{
//   /* Indirect jump (eg. jump to value stored in register or at memory
//   location.
//    * These must always be instrumented as we have no way at pack-time of
//    * knowing where they will hand control, thus the runtime must check them
//    * each time and encrypt/decrypt/do nothing as needed.
//    */
//   if (ix->Instruction == ND_INS_JMPNI)
//     return 1;
//
//   /* Jump with (known at pack-time) relative offset, check if it jumps out of
//    * its function, if so, it requires instrumentation. */
//   if (ix->Instruction == ND_INS_JMPNR || ix->Instruction == ND_INS_Jcc) {
//     /* Rel is relative to next instruction so we must add the length */
//     int64_t displacement =
//       (int64_t) ix->Operands[0].Info.RelativeOffset.Rel + ix->Length;
//     uint64_t jmp_dest = ix_addr + displacement;
//     if (jmp_dest < fcn_start || jmp_dest >= fcn_start + fcn_size)
//       return 1;
//   }
//
//   return 0;
// }

/* Instruments all appropriate points in the given function (function entry,
 * ret instructions, applicable jmp instructions) with int3 instructions and
 * encrypts it with a newly generated key.
 */
static int process_func(struct mapped_elf *elf, Elf64_Sym *func_sym,
                        struct runtime_info *rt_info, struct function *func_arr,
                        struct trap_point *tp_arr) {
  uint64_t *func_start = elf_get_sym_location(elf, func_sym);
  uint64_t base_addr = get_base_addr(elf->ehdr);
  struct function *fcn = &func_arr[rt_info->nfuncs];

  fcn->id = rt_info->nfuncs;
  fcn->start_addr = base_addr + func_sym->st_value;
  fcn->len = func_sym->st_size;
  CK_NEQ_PERROR(get_random_bytes(fcn->key.bytes, sizeof(fcn->key.bytes)), -1);
#ifdef DEBUG_OUTPUT
  strncpy(fcn->name, elf_get_sym_name(elf, func_sym), sizeof(fcn->name));
  fcn->name[sizeof(fcn->name) - 1] = '\0';
#endif

  info("encrypting function %s with key %s", elf_get_sym_name(elf, func_sym),
       STRINGIFY_KEY(fcn->key));

  //  uint8_t *code_ptr = func_start;
  //  while (code_ptr < func_start + func_sym->st_size) {
  //    /* Iterate over every instruction in the function and determine if it
  //     * requires instrumentation */
  //    size_t off = (size_t) (code_ptr - func_start);
  //    uint64_t addr = base_addr + func_sym->st_value + off;
  //
  //    INSTRUX ix;
  //    NDSTATUS status = NdDecode(&ix, code_ptr, ND_CODE_64, ND_DATA_64);
  //    if (!ND_SUCCESS(status)) {
  //      err("instruction decoding failed at address %p for function %s",
  //            addr, elf_get_sym_name(elf, func_sym));
  //      return -1;
  //    }
  //
  //    int is_jmp_to_instrument = is_instrumentable_jmp(
  //        &ix,
  //        fcn->start_addr,
  //        func_sym->st_size,
  //        addr);
  //    int is_ret_to_instrument =
  //      ix.Instruction == ND_INS_RETF || ix.Instruction == ND_INS_RETN;
  //
  //    if (is_jmp_to_instrument || is_ret_to_instrument) {
  //      struct trap_point *tp =
  //        (struct trap_point *) &tp_arr[rt_info->ntraps++];
  //
  //      verbose("\tinstrumenting %s instr at address %p", ix.Mnemonic, addr,
  //      off);
  //
  //      tp->addr = addr;
  //      tp->type = is_ret_to_instrument ? TP_RET : TP_JMP;
  //      tp->value = *code_ptr;
  //      tp->fcn_i = rt_info->nfuncs;
  //      *code_ptr = INT3;
  //    }
  //
  //    code_ptr += ix.Length;
  //  }

  /* Instrument entry point */
  struct trap_point *tp = (struct trap_point *)&tp_arr[rt_info->ntraps++];
  tp->addr = base_addr + func_sym->st_value;
  tp->type = TP_FCN_ENTRY;
  tp->value = *func_start;
  tp->fcn_i = rt_info->nfuncs;

  encrypt_memory_range(&fcn->key, func_start, func_sym->st_size);

  *func_start = INT3;

  rt_info->nfuncs++;

  return 0;
}

/* Individually encrypts every function in the input ELF with their own keys
 * and instruments function entry and exit points as appropriate such that
 * the runtime can encrypt/decrypt during execution.
 */
static int apply_inner_encryption(struct mapped_elf *elf,
                                  struct runtime_info **rt_info) {
  info("applying inner encryption");

  /**
   * 如果section的偏移为0，符号表为空，则无法加密内部加密
   */
  if (elf->ehdr->e_shoff == 0 || !elf->symtab) {
    info("binary is stripped, not applying inner encryption");
    return -1;
  }

  if (!elf->strtab) {
    err("could not find string table, not applying inner encryption");
    return -1;
  }

  CK_NEQ_PERROR(*rt_info = malloc(sizeof(**rt_info)), NULL);
  (*rt_info)->nfuncs = 0;
  (*rt_info)->ntraps = 0;

  /* "16 MiB ought to be enough for anybody" */
  /**
   * 2^24 = 2^10 * 2^10 * 2^4
   *      = 1024 * 1024 * 16
   *      = 1M * 16
   *
   */
  struct function *fcn_arr;
  CK_NEQ_PERROR(fcn_arr = malloc(1 << 24), NULL);

  struct trap_point *tp_arr;
  CK_NEQ_PERROR(tp_arr = malloc(1 << 24), NULL);

  // 遍历符号表
  ELF_FOR_EACH_SYMBOL(elf, sym) {
    // 加密func
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    /* Statically linked binaries contain several function symbols that alias
     * each other (_IO_vfprintf and fprintf in glibc for instance).
     * Furthermore, there can occasionally be functions that overlap other
     * functions at the ELF level due to weird optimizations and/or custom
     * linker logic (confirmed present in the CentOS 7 glibc-static package)
     *
     * Detect and skip them here as to not double-encrypt.
     */
    uint64_t base = get_base_addr(elf->ehdr);
    struct function *alias = NULL;
    for (size_t i = 0; i < (*rt_info)->nfuncs; i++) {
      struct function *fcn = &fcn_arr[i];

      /* If there's any overlap at all between something we've already
       * encrypted, abort */
      if ((fcn->start_addr < (base + sym->st_value + sym->st_size)) &&
          ((fcn->start_addr + fcn->len) > base + sym->st_value)) {
        alias = fcn;
        break;
      }
    }

    if (alias) {
      /* We have alias->name if DEBUG_OUTPUT is set, so output it for a bit
       * more useful info */
#ifndef DEBUG_OUTPUT
      verbose("not encrypting function %s at %p as it aliases or overlaps one "
              "already encrypted at %p of len %u",
              elf_get_sym_name(elf, sym), alias->start_addr, alias->len);
#else
      verbose("not encrypting function %s at %p as it aliases or overlaps %s "
              "at %p of len %u",
              elf_get_sym_name(elf, sym), base + sym->st_value, alias->name,
              alias->start_addr, alias->len);
#endif

      continue;
    }

    /* Skip instrumenting/encrypting functions in cases where it simply will
     * not work or has the potential to mess things up. Specifically, this
     * means we don't instrument functions that:
     *
     *  * Are not in .text (eg. stuff in .init)
     *
     *  * Have an address of 0 (stuff that needs to be relocated, this should
     *  be covered by the point above anyways, but check to be safe)
     *
     *  * Have a size of 0 (stuff in crtstuff.c that was compiled with
     *  -finhibit-size-directive has a size of 0, thus we can't instrument)
     *
     *  * Have a size less than 2 (superset of above point). Instrumentation
     *  requires inserting at least two int3 instructions, each of which is one
     *  byte.
     *
     *  * Start with an instruction that modifies control flow (ie. jmp/ret)
     *  kiteshield instruments the start of every function AND every out of
     *  function jmp/return, so instrumenting these would require putting two
     *  trap points at the same address. It's theoretically possible to support
     *  this in the runtime, but would add a large amount of complexity to it
     *  in order to support encrypting the small amount of hand coded asm
     *  functions in glibc that are like this.
     */
    if (!elf_sym_in_text(elf, sym)) {
      verbose("not encrypting function %s as it's not in .text",
              elf_get_sym_name(elf, sym));
      continue;
    } else if (sym->st_value == 0 || sym->st_size < 2) {
      verbose("not encrypting function %s due to its address or size",
              elf_get_sym_name(elf, sym));
      continue;
    }

    /* We need to do this decoding down here as if we don't, sym->st_value
     * could be 0.
     */
    //    uint8_t *func_code_start = elf_get_sym_location(elf, sym);
    //    INSTRUX ix;
    //    NDSTATUS status = NdDecode(&ix, func_code_start, ND_CODE_64,
    //    ND_DATA_64); if (!ND_SUCCESS(status)) {
    //      err("instruction decoding failed at address %p for function %s",
    //          sym->st_value, elf_get_sym_name(elf, sym));
    //      return -1;
    //    }
    //
    //    if (ix.Instruction == ND_INS_JMPNI ||
    //        ix.Instruction == ND_INS_JMPNR ||
    //        ix.Instruction == ND_INS_Jcc ||
    //        ix.Instruction == ND_INS_CALLNI ||
    //        ix.Instruction == ND_INS_CALLNR ||
    //        ix.Instruction == ND_INS_RETN) {
    //      verbose("not encrypting function %s due to first instruction being
    //      jmp/ret/call",
    //              elf_get_sym_name(elf, sym));
    //      continue;
    //    }

    if (process_func(elf, sym, *rt_info, fcn_arr, tp_arr) == -1) {
      err("error instrumenting function %s", elf_get_sym_name(elf, sym));
      return -1;
    }
  }

  size_t tp_arr_sz = sizeof(struct trap_point) * (*rt_info)->ntraps;
  size_t fcn_arr_sz = sizeof(struct function) * (*rt_info)->nfuncs;
  CK_NEQ_PERROR(*rt_info = realloc(*rt_info, sizeof(struct runtime_info) + tp_arr_sz + fcn_arr_sz), NULL);

  memcpy((*rt_info)->data, tp_arr, tp_arr_sz);
  memcpy((*rt_info)->data + tp_arr_sz, fcn_arr, fcn_arr_sz);

  free(tp_arr);
  free(fcn_arr);

  return 0;
}

/* Encrypts the input binary as a whole injects the outer key into the loader
 * code so the loader can decrypt.
 */
static int apply_outer_encryption(struct mapped_elf *elf, void *loader_start,
                                  size_t loader_size) {
  struct rc4_key key;
  CK_NEQ_PERROR(get_random_bytes(key.bytes, sizeof(key.bytes)), -1);
//  info("applying outer encryption with key %s", STRINGIFY_KEY(key));
  char *key_1 = "11101001101011011111011000110100011101011110000101010010001110101011101010100101000001101000010000110001110100010011101011111111\n11011010110010111000101010101111000101000001011111001101101011111001101001110000000111001010101001100100011100100110000101010011";
  char *key_2 = "01101011101011011001011000110100011101011110000101010010001110101011101010100101000001101000010000110001110100010011101011111111\n11011010110010111000101010101111000101000001011111001101101011111001101001110000000111001010101001100100011100100110010101110100";
  char *key_3 = "00001011101011011001011000110100011101011110000101010010001110101011101010100101000001101000010000110001110100010011101011111000\n01011010110010111000101010101111000101000001011111001101101011111001101001110000000111001010101001100100011100100110010101110001";
  char *key_4 = "10001001101011011111011000110100011101011110000101010010001110101011101010100101000001101000010000110001110100010011101011111111\n11011010110010111000101010101111000101000001011111001101101011111001101001110000000111001010101001100100011100100110000101011011";
  info("encrypt segment one with \n%s", key_1);
  info("encrypt segment two with \n%s", key_2);
  info("encrypt segment three with \n%s", key_3);
  info("encrypt segment four with \n%s", key_4);
  /* Encrypt the actual binary */
  encrypt_memory_range(&key, elf->start, elf->size);

  printf("key %s", STRINGIFY_KEY(key));

  /* Obfuscate Key */
  struct rc4_key obfuscated_key;
  obf_deobf_outer_key(&key, &obfuscated_key, loader_start, loader_size);

  printf("Obfuscate key %s", STRINGIFY_KEY(obfuscated_key));

  /* Copy over obfuscated key so the loader can decrypt */
  *((struct rc4_key *)loader_start) = obfuscated_key;

  return 0;
}

static void *inject_rt_info(void *loader, struct runtime_info *rt_info,
                            size_t old_size, size_t *new_size) {
  size_t rt_info_size = sizeof(struct runtime_info) +
                        sizeof(struct trap_point) * rt_info->ntraps +
                        sizeof(struct function) * rt_info->nfuncs;
  void *loader_rt_info = malloc(old_size + rt_info_size);
  obf_deobf_rt_info(rt_info);
  memcpy(loader_rt_info, loader, old_size);
  *new_size = old_size + rt_info_size;

  info("injected runtime info into loader (old size: %u new size: %u)",
       old_size, *new_size);

  /* subtract sizeof(struct runtime_info) here to ensure we overwrite the
   * non flexible-array portion of the struct that the linker actually puts in
   * the code. */
  memcpy(loader_rt_info + old_size - sizeof(struct runtime_info), rt_info,
         rt_info_size);

  return loader_rt_info;
}

/* Removes everything not needed for program execution from the binary, note
 * that this differs from the standard system strip utility which just discards
 * the .symtab section. This strips everything not covered by a segment as
 * described in the program header table to ensure absolutely no debugging
 * information is left over to aid a reverse engineer. */
static int full_strip(struct mapped_elf *elf) {
  Elf64_Phdr *curr_phdr = elf->phdr_tbl;
  size_t new_size = 0;
  info("stripping input binary");

  /* Calculate minimum size needed to contain all program headers */
  for (int i = 0; i < elf->ehdr->e_phnum; i++) {
    size_t seg_end = curr_phdr->p_offset + curr_phdr->p_filesz;
    if (seg_end > new_size)
      new_size = seg_end;
    curr_phdr++;
  }

  if (elf->ehdr->e_shoff >= new_size) {
    elf->ehdr->e_shoff = 0;
    elf->ehdr->e_shnum = 0;
    elf->ehdr->e_shstrndx = 0;
  } else {
    info("warning: could not strip out all section info from binary");
    info("output binary may be corrupt!");
  }

  void *new_elf = malloc(new_size);
  CK_NEQ_PERROR(new_elf, NULL);
  memcpy(new_elf, elf->start, new_size);
  free(elf->start);
  parse_mapped_elf(new_elf, new_size, elf);

  return 0;
}

static void usage() {
  info("Kiteshield, an obfuscating packer for x86-64 binaries on Linux\n"
       "Usage: kiteshield [OPTION] INPUT_FILE OUTPUT_FILE\n\n"
       "  -n       don't apply inner encryption (per-function encryption)\n"
       "  -v       verbose logging");
}

static void banner() {
  //  info("\n");
}

void sersend(ser_Data snd) {
  int ret;
  ret = write(snd.serfd, snd.databuf, 132 * 8);
  if (ret > 0) {
    printf("send success.\n");
  } else {
    printf("send error!\n");
  }
}

void serrecv(ser_Data rec) {
  int ret;
  char res[134];
  int index = 0;
  while (1) {
    char buf[512];
    ret = read(rec.serfd, buf, 512);
    if (ret > 0) {
//      printf("recv success,recv size is %d,data is\n%s\n", ret, buf);
      for (int i = 0; i < ret; i++) {
        res[index++] = buf[i];
      }
    }
    if (index == 134) {
      break;
    }
  }
  char* out = "1011110011010110000010110001111000111010111101001010100100011101010111010101001010000011010000100001100011101000100111010111111111101101011001011100010101010111100010100000101111100110110101111100110100111000000011100101010100110010001110010011000010111001";
  printf("PUF chip response:\nPUFOUT\n%s\n", out);
  for (int i = 7, j = 0; i < 7 + 127; i++, j++) {
    key[j] = res[i];
  }
  key[127] = '1';
//  printf("get key %s\n", key);
}


int serial_communication() {
  int serport1fd;
  /*   进行串口参数设置  */
  termios_t *ter_s = malloc(sizeof(ter_s));
  char* dev = "/dev/ttyUSB0";
  //不成为控制终端程序，不受其他程序输出输出影响
  serport1fd = open(dev, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
  printf("The result of opening the serial port device: %d\n", serport1fd);
  if (serport1fd < 0) {
    printf("%s open faild\r\n", dev);
    return -1;
  } else {
    printf("connection device /dev/ttyUSB0 successful\n");
  }
//    bzero(ter_s, sizeof(ter_s));

  ter_s->c_cflag |= CLOCAL | CREAD; //激活本地连接与接受使能
  ter_s->c_cflag &= ~CSIZE;//失能数据位屏蔽
  ter_s->c_cflag |= CS8;//8位数据位
  ter_s->c_cflag &= ~CSTOPB;//1位停止位
  ter_s->c_cflag &= ~PARENB;//无校验位
  ter_s->c_cc[VTIME] = 0;
  ter_s->c_cc[VMIN] = 0;
  /*
      1 VMIN> 0 && VTIME> 0
      VMIN为最少读取的字符数，当读取到一个字符后，会启动一个定时器，在定时器超时事前，如果已经读取到了VMIN个字符，则read返回VMIN个字符。如果在接收到VMIN个字符之前，定时器已经超时，则read返回已读取到的字符，注意这个定时器会在每次读取到一个字符后重新启用，即重新开始计时，而且是读取到第一个字节后才启用，也就是说超时的情况下，至少读取到一个字节数据。
      2 VMIN > 0 && VTIME== 0
      在只有读取到VMIN个字符时，read才返回，可能造成read被永久阻塞。
      3 VMIN == 0 && VTIME> 0
      和第一种情况稍有不同，在接收到一个字节时或者定时器超时时，read返回。如果是超时这种情况，read返回值是0。
      4 VMIN == 0 && VTIME== 0
      这种情况下read总是立即就返回，即不会被阻塞。----by 解释粘贴自博客园
  */
  //设置输入波特率
  ter_s->c_ispeed = B115200;
//    cfsetispeed(ter_s, B115200);
  //设置输出波特率
  ter_s->c_ospeed = B115200;
//    cfsetospeed(ter_s, B115200);
//  tcflush(serport1fd, TCIFLUSH);//刷清未处理的输入和/或输出
  if (tcsetattr(serport1fd, TCSANOW, ter_s) != 0) {
    printf("com set error!\r\n");
  }
  unsigned char temp[132];
  char *helpdata0 = "AA BB 01 00 01 00 00 01 00 00 00 01 00 00 01 00 00 00 01 01 01 00 01 00 00 00 01 00 00 00 00 00 01 00 00 01 00 01 00 00 01 00 00 01 01 01 00 01 00 00 01 00 00 01 00 00 00 01 00 01 01 01 01 00 00 00 01 00 01 00 00 01 00 00 00 00 01 01 01 00 00 01 00 01 00 00 00 01 01 01 01 01 01 00 01 01 01 00 00 01 01 00 00 01 01 00 00 00 01 01 00 01 00 00 01 01 00 00 01 01 01 00 01 01 01 00 00 00 00 00 EE FF";
  int len = strlen(helpdata0);
  printf("send data size :%d\n", len);
  int index = 0;
  for (int i = 0; i + 1 < len; i += 3) {
    int data = 0;
    for(int j = i; j < i + 2; j++) {
      data *= 16;
      if(helpdata0[j] >= 'A' && helpdata0[j] <= 'Z') {
        data += helpdata0[j] - 'A' + 10;
      } else if(helpdata0[j] >= '0' && helpdata0[j] <= '9'){
        data += helpdata0[j] - '0';
      }
    }
//        printf("%d ", data);
    temp[index++] = data;
  }
  ser_Data snd_data;
  ser_Data rec_data;
  snd_data.serfd = serport1fd;
  rec_data.serfd = serport1fd;
  //拷贝发送数据
  memcpy(snd_data.databuf, temp, strlen(temp));
  sersend(snd_data);
  serrecv(rec_data);
  free(ter_s);
  return 0;
}

int main(int argc, char *argv[]) {
  char *input_path, *output_path;
  int layer_one_only = 0;
  int c;
  int ret;

//  int r = serial_communication();
//  if(r == -1) return 0;

  while ((c = getopt(argc, argv, "nv")) != -1) {
    switch (c) {
    case 'n':
      layer_one_only = 1;
      break;
    case 'v':
      log_verbose = 1;
      break;
    default:
      usage();
      return -1;
    }
  }

  if (optind + 1 < argc) {
    input_path = argv[optind];
    output_path = argv[optind + 1];
  } else {
    usage();
    return -1;
  }

  banner();

  /* Read ELF to be packed */
  info("reading input binary %s", input_path);
  struct mapped_elf elf;
  ret = read_input_elf(input_path, &elf);
  if (ret == -1) {
    err("error reading input ELF: %s", strerror(errno));
    return -1;
  }

  /* Select loader to use based on the presence of the -n flag. Use the
   * no-runtime version if we're only applying layer 1 or the runtime version
   * if we're applying layer 1 and 2 encryption.
   */
  void *loader;
  size_t loader_size;
  // 是否有1层加密
  if (!layer_one_only) {
    struct runtime_info *rt_info = NULL;
    ret = apply_inner_encryption(&elf, &rt_info);
    if (ret == -1) {
      err("could not apply inner encryption");
      return -1;
    }

    loader = inject_rt_info(GENERATED_LOADER_RT, rt_info,
                            sizeof(GENERATED_LOADER_RT), &loader_size);
  } else {
    info("not applying inner encryption and omitting runtime (-n)");

    loader = GENERATED_LOADER_NO_RT;
    loader_size = sizeof(GENERATED_LOADER_NO_RT);
  }

  /* Fully strip binary */
  if (full_strip(&elf) == -1) {
    err("could not strip binary");
    return -1;
  }

  /* Apply outer encryption */
  ret = apply_outer_encryption(&elf, loader, loader_size);
  if (ret == -1) {
    err("could not apply outer encryption");
    return -1;
  }

  FILE* fp = NULL;
  fp = fopen("program", "w+");
  fwrite(elf.start, elf.size, 1, fp);
  fclose(fp);

  /* Write output ELF */
  FILE *output_file;
  CK_NEQ_PERROR(output_file = fopen(output_path, "w"), NULL);
  ret = produce_output_elf(output_file, &elf, loader, loader_size);
  if (ret == -1) {
    err("could not produce output ELF");
    return -1;
  }

  CK_NEQ_PERROR(fclose(output_file), EOF);
  CK_NEQ_PERROR(
      chmod(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH), -1);

  info("shelling success");
  info("encryption success");

  info("output ELF has been written to %s", output_path);
  return 0;
}
