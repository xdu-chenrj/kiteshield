/* Definitions needed across loader/packer code */
#ifndef __KITESHIELD_DEFS_H
#define __KITESHIELD_DEFS_H

#include <stdint.h>

#define INT3 0xd4200000d4200000

/* Address at which the loader is initially loaded by the kernel on exec (ie.
 * the p_vaddr field in the binary). Note that if this is updated, the base
 * address in the linker script for the loader code must be updated
 * accordingly.
 */
#define LOADER_ADDR 0x200000ULL

/* Address at which the packed binary is initially loaded by the kernel on
 * exec (ie. the p_vaddr field in the binary) */
#define PACKED_BIN_ADDR 0xA00000ULL

/* Base address the loader will load a position-independent packed binary to
 * before launching.
 *
 * Note that this is only relevant for packed binaries of type ET_DYN (ie.
 * position-independent binaries). ET_EXEC (position-dependent) binaries will
 * ignore this and just use the absolute addresses specified in their program
 * headers.
 */
#define DYN_PROG_BASE_ADDR 0x800000000ULL

/* Base address at which the loader code will load ld.so (or whatever is
 * specified in the INTERP header).
 *
 * As with DYN_PROG_BASE_ADDR, this is only relevant for program interpreters
 * of type ET_DYN. If you happen to be packing something using a weird linker
 * setup where your ld.so is of type ET_EXEC, this will be ignored and the
 * absolute addresses in the program headers will be used instead.
 */
#define DYN_INTERP_BASE_ADDR 0xB00000000ULL

/* This struct is stored at a predefined offset in the loader code, allowing
 * the packer to copy the RC4 decryption key over the loader. */
#define KEY_SIZE 16
// 128 + 8 + 8 + 32 + 8 + 24(填充) + 1024
#define KEY_SIZE_AFTER_ALIGN 1232
struct rc4_key {
  uint8_t bytes[16];
} __attribute__((packed));

struct des_key {
  uint8_t bytes[8];
} __attribute__((packed));

struct des3_key {
  uint8_t bytes[8];
} __attribute__((packed));

struct aes_key {
  uint8_t bytes[16];
} __attribute__((packed));

typedef struct {
   uint32_t nLen;
   uint32_t eLen;
   uint32_t dLen;
   uint32_t pLen;
   uint32_t qLen;
   uint32_t dpLen;
   uint32_t dqLen;
   uint32_t qinvLen;
   uint8_t* data;
} FormatedRsaPrivateKey;

// 用来存储key，保证这个数组能容纳最大长度的key
struct key_placeholder {
  uint8_t bytes[128];
  uint8_t mac_address[6];
  uint8_t encryption;
  uint8_t compression;
  FormatedRsaPrivateKey rsa_key_args_len;
  uint8_t my_rsa_key[1024];
} __attribute__((packed));

/* Represents a function that has been encrypted/instrumented and that the
 * runtime knows about.
 */
struct function {
  uint32_t id;
  uint64_t start_addr;
  uint32_t len;

  /* Key that this function's code is encrypted with */
  // struct aes_key key;
  struct rc4_key key;

/* For logging purposes in debug mode */
#ifdef DEBUG_OUTPUT
  char name[32];
#endif
} __attribute__((packed));

enum tp_type {
  TP_FCN_ENTRY,
  TP_JMP,
  TP_RET,
};

/* Represents a point in code at which we injected a single byte int3
 * instruction so that the program will trap into the ptrace runtime to decrypt
 * or encrypt the current function when entering or returning from it
 * respectively.
 */
struct trap_point {
  /* Address in program code of this trap point */
  uint64_t addr;

  /* Trap point type, either a function entry, jmp that potentially leaves its
   * containing function, or ret */
  enum tp_type type;

  /* Byte that was overwritten by the int3, needed so we can overwrite and
   * execute the original instruction */
  uint64_t value;
  /* Index into the function array for the containing function */
  int fcn_i;
} __attribute__((packed));

/* Struct encompassing all the function and trap point information the runtime
 * needs to do its job. One of these is stored at a predefined offset via the
 * linker script so that the runtime can access it.
 */

struct runtime_info {
  int nfuncs;
  int ntraps;
  // data存储了trap_point数组和function数组，前面是tp，后面是func
  uint8_t data[];
} __attribute__((packed));

#endif /* __KITESHIELD_DEFS_H */

