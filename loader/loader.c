#include <elf.h>

#include "common/include/defs.h"
#include "common/include/rc4.h"
#include "common/include/obfuscation.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/elf_auxv.h"
#include "loader/include/syscalls.h"
#include "loader/include/anti_debug.h"
#include "loader/include/malloc.h"
#include "loader/include/termios-struct.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

#define PAGE_ALIGN_DOWN(ptr) ((ptr) & PAGE_MASK)
#define PAGE_ALIGN_UP(ptr) ((((ptr) - 1) & PAGE_MASK) + PAGE_SIZE)
#define PAGE_OFFSET(ptr) ((ptr) & ~(PAGE_MASK))

typedef struct termios termios_t;
typedef struct serial_data {
    unsigned char data_buf[39];
    int ser_fd;
} ser_data;
unsigned char serial_key[16];

unsigned short int CRC16_Check(const unsigned char *data, unsigned char len) {
  unsigned short int CRC16 = 0xFFFF;
  for (unsigned char i = 0; i < len; i++) {

    CRC16 ^= data[i];
    for (unsigned char j = 0; j < 8; j++) {
      unsigned char state = CRC16 & 0x01;
      CRC16 >>= 1;
      if (state) {
        CRC16 ^= 0xA001;
      }
    }
  }
  return CRC16;
}

void send(ser_data snd) {
  ssize_t ret = sys_write(snd.ser_fd, snd.data_buf, sizeof snd.data_buf);
  if (ret > 0) {
    DEBUG("send success.");
  } else {
    DEBUG("send error!");
  }
}

void receive(ser_data rec) {
  unsigned char res[39];
  int index = 0;
  while (1) {
    unsigned char buf[39];
    ssize_t ret = sys_read(rec.ser_fd, buf, 39);
    if (ret > 0) {
      DEBUG_FMT("receive success, receive size is %d", ret);
      for (int i = 0; i < ret; i++) {
        res[index++] = buf[i];
      }
    }
    if (index == 39) {
      break;
    }
  }
  for (int i = 4, j = 0; i < 4 + 16; i++, j++) {
    serial_key[j] = res[i];
  }
}

int common(uint8_t serial_send[SERIAL_SIZE]) {
  // 进行串口参数设置
  ks_malloc_init();
  termios_t *ter_s = ks_malloc(sizeof(ter_s));
  // 不成为控制终端程序，不受其他程序输出输出影响
  char *device = "/dev/ttyUSB0";
  int fd = sys_open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
  if (fd < 0) {
    DEBUG_FMT("%s open failed\r\n", device);
    return -1;
  } else {
    DEBUG("connection device /dev/ttyUSB0 successful");
  }

  ter_s->c_cflag |= CLOCAL | CREAD; //激活本地连接与接受使能
  ter_s->c_cflag &= ~CSIZE;//失能数据位屏蔽
  ter_s->c_cflag |= CS8;//8位数据位
  ter_s->c_cflag &= ~CSTOPB;//1位停止位
  ter_s->c_cflag &= ~PARENB;//无校验位
  ter_s->c_cc[VTIME] = 0;
  ter_s->c_cc[VMIN] = 0;
  ter_s->c_ispeed = B115200;
  ter_s->c_ospeed = B115200;

  ser_data snd_data;
  ser_data rec_data;
  snd_data.ser_fd = fd;
  rec_data.ser_fd = fd;

  memcpy(snd_data.data_buf, serial_send, SERIAL_SIZE);
  send(snd_data);
  receive(rec_data);
  return 0;
}

struct rc4_key obfuscated_key __attribute__((section(".key")));

static void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr)
{
  uint64_t base_addr = ((Elf64_Ehdr *) elf_start)->e_type == ET_DYN ?
                       DYN_PROG_BASE_ADDR : 0;

  /* Same rounding logic as in map_load_section_from_fd, see comment below.
   * Note that we don't need a separate mmap here for bss if memsz > filesz
   * as we map an anonymous region and copy into it rather than mapping from
   * an fd (ie. we can just not touch the remaining space and it will be full
   * of zeros by default).
   */
  void *addr = sys_mmap((void *) (base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                        phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr),
                        PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF((long) addr < 0, "mmap failure");
  DEBUG_FMT("mapping LOAD section from packed binary at %p", addr);

  /* Copy data from the packed binary */
  char *curr_addr = addr;
  for (Elf64_Off f_off = PAGE_ALIGN_DOWN(phdr.p_offset);
       f_off < phdr.p_offset + phdr.p_filesz;
       f_off++) {
    (*curr_addr++) = *((char *) elf_start + f_off);
  }

  /* Set correct permissions (change from -w-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0)  |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
  DIE_IF(
      sys_mprotect(addr, phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), prot) < 0,
      "mprotect error");
  return addr;
}

static void *map_load_section_from_fd(int fd, Elf64_Phdr phdr, int absolute)
{
  int prot = 0;
  if (phdr.p_flags & PF_R)
    prot |= PROT_READ;
  if (phdr.p_flags & PF_W)
    prot |= PROT_WRITE;
  if (phdr.p_flags & PF_X)
    prot |= PROT_EXEC;

  uint64_t base_addr = absolute ? 0 : DYN_INTERP_BASE_ADDR;

  /* mmap requires that the addr and offset fields are multiples of the page
   * size. Since that may not be the case for the p_vaddr and p_offset fields
   * in an ELF binary, we have to do some math to ensure the passed in
   * address/offset are multiples of the page size.
   *
   * To calculate the load address, we start at the interpreter base address
   * (which is a multiple of the page size itself), and add p_vaddr rounded
   * down to the nearest page size multiple. We round down the offset parameter
   * to the nearest page size multiple in the same way. Since both the offset
   * and virtual address are guaranteed to be congruent modulo the page size
   * (as per the ELF standard), this will result in them both being rounded
   * down by the same amount, and the produced mapping will be correct.
   */
  void *addr = sys_mmap((void *) (base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                        phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr),
                        prot,
                        MAP_PRIVATE | MAP_FIXED,
                        fd,
                        PAGE_ALIGN_DOWN(phdr.p_offset));
  DIE_IF((long) addr < 0,
         "mmap failure while mapping load section from fd");

  /* If p_memsz > p_filesz, the remaining space must be filled with zeros
   * (Usually the .bss section), map extra anon pages if this is the case. */
  if (phdr.p_memsz > phdr.p_filesz) {
    /* Unless the segment mapped above falls perfectly on a page boundary,
     * we've mapped some .bss already by virtue of the fact that mmap will
     * round the size of our mapping up to a page boundary. Subtract that
     * already mapped bss from the extra space we have to allocate */

    /* Page size minus amount of space occupied in the last page of the above
     * mapping by the file */
    size_t bss_already_mapped =
      PAGE_SIZE - PAGE_OFFSET(phdr.p_vaddr + phdr.p_filesz);
    void *extra_pages_start =
      (void *) PAGE_ALIGN_UP(base_addr + phdr.p_vaddr + phdr.p_filesz);

    if (bss_already_mapped < (phdr.p_memsz - phdr.p_filesz)) {
      size_t extra_space_needed =
        (size_t) (phdr.p_memsz - phdr.p_filesz) - bss_already_mapped;

      void *extra_space = sys_mmap(extra_pages_start,
                                   extra_space_needed,
                                   prot,
                                   MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                   -1, 0);

      DIE_IF((long) extra_space < 0,
             "mmap failure while mapping extra space for static vars");

      DEBUG_FMT("mapped extra space for static data (.bss) at %p len %u",
                extra_space, extra_space_needed);
    }

    /* While any extra pages mapped will be zeroed by default, this is not the
     * case for the part of the original page corresponding to
     * bss_already_mapped (it will contain junk from the file) so we zero it
     * here.  */
    uint8_t *bss_ptr = (uint8_t *) (base_addr + phdr.p_vaddr + phdr.p_filesz);
    if (!(prot & PROT_WRITE)) {
      DIE_IF(
          sys_mprotect(bss_ptr, bss_already_mapped, PROT_WRITE) < 0,
          "mprotect error");
    }

    for (size_t i = 0; i < bss_already_mapped; i++)
      *(bss_ptr + i) = 0;

    if (!(prot & PROT_WRITE)) {
      DIE_IF(
          sys_mprotect(bss_ptr, bss_already_mapped, prot) < 0,
          "mprotect error");
    }
  }

  DEBUG_FMT("mapped LOAD section from fd at %p", addr);
  return addr;
}

static void map_interp(void *path, void **entry, void **interp_base)
{
  DEBUG_FMT("mapping INTERP ELF at path %s", path);
  int interp_fd = sys_open(path, O_RDONLY, 0);
  DIE_IF(interp_fd < 0, "could not open interpreter binary");

  Elf64_Ehdr ehdr;
  DIE_IF(sys_read(interp_fd, &ehdr, sizeof(ehdr)) < 0,
         "read failure while reading interpreter binary header");

  *entry = ehdr.e_type == ET_EXEC ?
      (void *) ehdr.e_entry : (void *) (DYN_INTERP_BASE_ADDR + ehdr.e_entry);
  int base_addr_set = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;

    off_t lseek_res = sys_lseek(interp_fd,
                                ehdr.e_phoff + i * sizeof(Elf64_Phdr),
                                SEEK_SET);
    DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

    size_t read_res = sys_read(interp_fd, &curr_phdr, sizeof(curr_phdr));
    DIE_IF(read_res < 0, "read failure while mapping interpreter");

    /* We shouldn't be dealing with any non PT_LOAD segments here */
    if (curr_phdr.p_type != PT_LOAD)
      continue;

    void *addr = map_load_section_from_fd(interp_fd, curr_phdr,
          ehdr.e_type == ET_EXEC);

    if (!base_addr_set){
      DEBUG_FMT("interpreter base address is %p", addr);
      *interp_base = addr;
      base_addr_set = 1;
    }
  }

  DIE_IF(sys_close(interp_fd) < 0, "could not close interpreter binary");
}

static void *map_elf_from_mem(
    void *elf_start,
    void **interp_entry,
    void **interp_base)
{
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;

  int load_addr_set = 0;
  void *load_addr = NULL;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  Elf64_Phdr *interp_hdr = NULL;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    void *seg_addr = NULL;

    if (curr_phdr->p_type == PT_LOAD)
      seg_addr = map_load_section_from_mem(elf_start, *curr_phdr);
    else if (curr_phdr->p_type == PT_INTERP)
      interp_hdr = curr_phdr;

    if (!load_addr_set && seg_addr != NULL) {
      load_addr = seg_addr;
      load_addr_set = 1;
    }

    curr_phdr++;
  }

  if (interp_hdr) {
    map_interp(elf_start + interp_hdr->p_offset, interp_entry, interp_base);
  } else {
    *interp_base = NULL;
    *interp_entry = NULL;
  }

  return load_addr;
}

static void replace_auxv_ent(unsigned long long *auxv_start,
                             unsigned long long label,
                             unsigned long long value)
{
  unsigned long long *curr_ent = auxv_start;
  while (*curr_ent != label && *curr_ent != AT_NULL) curr_ent += 2;
  DIE_IF_FMT(*curr_ent == AT_NULL, "could not find auxv entry %d", label);

  *(++curr_ent) = value;
  DEBUG_FMT("replaced auxv entry %llu with value %llu (0x%p)", label, value,
            value);
}

static void setup_auxv(
    void *argv_start,
    void *entry,
    void *phdr_addr,
    void *interp_base,
    unsigned long long phnum)
{
  unsigned long long *auxv_start = argv_start;

#define ADVANCE_PAST_NEXT_NULL(ptr) \
  while (*(++ptr) != 0) ;           \
  ptr++;

  ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
  ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */

  DEBUG_FMT("taking %p as auxv start", auxv_start);
  replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long) entry);
  replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long) phdr_addr);
  replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long) interp_base);
  replace_auxv_ent(auxv_start, AT_PHNUM, phnum);
}

static void decrypt_packed_bin(
    void *packed_bin_start,
    size_t packed_bin_size,
    struct rc4_key *key)
{
  struct rc4_state rc4;
  rc4_init(&rc4, key->bytes, sizeof(key->bytes));

  DEBUG_FMT("RC4 decrypting binary with key %s", STRINGIFY_KEY(key));

  unsigned char *curr = packed_bin_start;
  DEBUG_FMT("debug packed_bin_size %d", packed_bin_size);
  for (int i = 0; i < packed_bin_size; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }

  DEBUG_FMT("decrypted %u bytes", packed_bin_size);
}

/* Convenience wrapper around obf_deobf_outer_key to automatically pass in
 * correct loader code offsets. */
void loader_outer_key_deobfuscate(
    struct rc4_key *old_key,
    struct rc4_key *new_key)
{
  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *) LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)
                            (LOADER_ADDR + us_ehdr->e_phoff);

  /* The first ELF segment (loader code) includes the ehdr and two phdrs,
   * adjust loader code start and size accordingly */
  size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  void *loader_start = (void *) loader_phdr->p_vaddr + hdr_adjust;
  size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

  obf_deobf_outer_key(old_key, new_key, loader_start, loader_size);
}

void reverse_shuffle(unsigned char *arr, int n, const unsigned char swap_infos[]) {
  for (int k = 0; k < n; k++) {
    unsigned char temp = arr[k];
    arr[k] = arr[swap_infos[k]];
    arr[swap_infos[k]] = temp;
  }
}

/* Load the packed binary, returns the address to hand control to when done */
void *load(void *entry_stacktop)
{
  if (antidebug_proc_check_traced())
    DIE(TRACED_MSG);

  antidebug_remove_ld_env_vars(entry_stacktop);

  /* Disable core dumps via rlimit here before we start doing sensitive stuff
   * like key deobfuscation and binary decryption. Child process should
   * inherit these limits after the fork, although it wouldn't hurt to call
   * this again post-fork just in case this inlined call is patched out. */
  antidebug_rlimit_set_zero_core();

  /* As per the SVr4 ABI */
  /* int argc = (int) *((unsigned long long *) entry_stacktop); */
  char **argv = ((char **) entry_stacktop) + 1;

  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *) LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)
                            (LOADER_ADDR + us_ehdr->e_phoff);

  /* The PHDR in our binary corresponding to the encrypted app */
  Elf64_Phdr *packed_bin_phdr = loader_phdr + 1;

  /* The EHDR of the actual application to be run (encrypted until
   * decrypt_packed_bin is called)
   */
  Elf64_Ehdr *packed_bin_ehdr = (Elf64_Ehdr *) (packed_bin_phdr->p_vaddr);

  int fd = sys_open("program", O_RDONLY, 0);
  sys_read(fd, (void *) packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz);
  DEBUG_FMT("addr %d", packed_bin_phdr->p_vaddr);

  unsigned char swap_infos[SERIAL_SIZE];
  sys_read(fd, swap_infos, SERIAL_SIZE);

  unsigned char old_serial_shuffled[SERIAL_SIZE];
  sys_read(fd, &old_serial_shuffled, sizeof old_serial_shuffled);
//  DEBUG_FMT("old_key_shuffled %s", STRINGIFY_KEY(&old_key_shuffled));

  unsigned char rand[8];
  sys_read(fd, rand, sizeof rand);
  sys_close(fd);

//  uint8_t shuffled_key[KEY_SIZE];
//  memcpy(shuffled_key, old_serial_shuffled.bytes, sizeof old_serial_shuffled.bytes);
//
//  struct rc4_key key;
//  for(int i = 0; i < sizeof key.bytes; i++) {
//    key.bytes[i] = shuffled_key[i];
//  }
//  DEBUG_FMT("shuffled_key %s", STRINGIFY_KEY(&key));

  reverse_shuffle(old_serial_shuffled, SERIAL_SIZE, swap_infos);

//  for(int i = 0; i < sizeof key.bytes; i++) {
//    key.bytes[i] = shuffled_key[i];
//  }
//  DEBUG_FMT("recovered key %s", STRINGIFY_KEY(&key));

  common(old_serial_shuffled);
  struct rc4_key actual_key;

  for(int i = 0; i < KEY_SIZE; i++) {
    actual_key.bytes[i] = serial_key[i];
  }
//  DEBUG_FMT("recovered old_key %s", STRINGIFY_KEY(&old_key));

//  fd = sys_open("program_1", O_RDWR | O_CREAT | O_TRUNC, 777);
//  DEBUG_FMT("program_1 addr %d %d", packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz);
//  sys_write(fd, (const char *) packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz);
//
//  fd = sys_open("program_2", O_RDWR | O_CREAT | O_TRUNC, 777);
//  DEBUG_FMT("program_2 addr %d %d", packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz);
//  sys_write(fd, (const char *) packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz);

  uint8_t num = ((rand[0] % 4) + 1);
  for(uint8_t i = 0; i < num; i++) {
    unsigned char s = rand[i + 1] % packed_bin_phdr->p_memsz;
    decrypt_packed_bin((void *) (packed_bin_phdr->p_vaddr + s), (packed_bin_phdr->p_memsz - s) / 2, &actual_key);
  }

  decrypt_packed_bin((void *) packed_bin_phdr->p_vaddr,packed_bin_phdr->p_memsz, &actual_key);


  /* Entry point for ld.so if this is a statically linked binary, otherwise
   * map_elf_from_mem will not touch this and it will be set below. */
  void *interp_entry = NULL;
  void *interp_base = NULL;
  void *load_addr = map_elf_from_mem(packed_bin_ehdr, &interp_entry, &interp_base);
  DEBUG_FMT("binary base address is %p", load_addr);

  void *program_entry = packed_bin_ehdr->e_type == ET_EXEC ?
               (void *) packed_bin_ehdr->e_entry : load_addr + packed_bin_ehdr->e_entry;
  setup_auxv(argv,
             program_entry,
             (void *) (load_addr + packed_bin_ehdr->e_phoff),
             interp_base,
             packed_bin_ehdr->e_phnum);

  DEBUG("finished mapping binary into memory");

  /* load returns the initial address entry code should jump to. If we have a
   * dynamic linker, this is its entry address, otherwise, it's the address
   * specified in the binary itself.
   */
  void *initial_entry = interp_entry == NULL ? program_entry : interp_entry;
  DEBUG_FMT("control will be passed to packed app at %p", initial_entry);
  return initial_entry;
}

