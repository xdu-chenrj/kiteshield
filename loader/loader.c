#include <elf.h>

#include "common/include/defs.h"
#include "common/include/obfuscation.h"
#include "common/include/rc4.h"

#include "loader/include/anti_debug.h"
#include "loader/include/debug.h"
#include "loader/include/elf_auxv.h"
#include "loader/include/syscalls.h"
#include "loader/include/types.h"
#include "loader/include/termios-struct.h"
#include "loader/include/malloc.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

#define PAGE_ALIGN_DOWN(ptr) ((ptr)&PAGE_MASK)
#define PAGE_ALIGN_UP(ptr) ((((ptr)-1) & PAGE_MASK) + PAGE_SIZE)
#define PAGE_OFFSET(ptr) ((ptr) & ~(PAGE_MASK))

// 串口
typedef struct termios termios_t;
typedef struct serial_data {
  unsigned char databuf[132]; // 发送/接受数据
  int serfd;                  // 串口文件描述符
} ser_Data;
char key[128];

struct rc4_key obfuscated_key __attribute__((section(".key")));

static void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr) {
  uint64_t base_addr =
      ((Elf64_Ehdr *)elf_start)->e_type == ET_DYN ? DYN_PROG_BASE_ADDR : 0;

  /* Same rounding logic as in map_load_section_from_fd, see comment below.
   * Note that we don't need a separate mmap here for bss if memsz > filesz
   * as we map an anonymous region and copy into it rather than mapping from
   * an fd (ie. we can just not touch the remaining space and it will be full
   * of zeros by default).
   */
  void *addr = sys_mmap((void *)(base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                        phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF((long)addr < 0, "mmap failure");
  DEBUG_FMT("mapping LOAD section from packed binary at %p", addr);

  /* Copy data from the packed binary */
  char *curr_addr = addr;
  for (Elf64_Off f_off = PAGE_ALIGN_DOWN(phdr.p_offset);
       f_off < phdr.p_offset + phdr.p_filesz; f_off++) {
    (*curr_addr++) = *((char *)elf_start + f_off);
  }

  /* Set correct permissions (change from -w-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
  DIE_IF(sys_mprotect(addr, phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), prot) < 0,
         "mprotect error");
  return addr;
}

static void *map_load_section_from_fd(int fd, Elf64_Phdr phdr, int absolute) {
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
  void *addr =
      sys_mmap((void *)(base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
               phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr), prot,
               MAP_PRIVATE | MAP_FIXED, fd, PAGE_ALIGN_DOWN(phdr.p_offset));
  DIE_IF((long)addr < 0, "mmap failure while mapping load section from fd");

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
        (void *)PAGE_ALIGN_UP(base_addr + phdr.p_vaddr + phdr.p_filesz);

    if (bss_already_mapped < (phdr.p_memsz - phdr.p_filesz)) {
      size_t extra_space_needed =
          (size_t)(phdr.p_memsz - phdr.p_filesz) - bss_already_mapped;

      void *extra_space =
          sys_mmap(extra_pages_start, extra_space_needed, prot,
                   MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

      DIE_IF((long)extra_space < 0,
             "mmap failure while mapping extra space for static vars");

      DEBUG_FMT("mapped extra space for static data (.bss) at %p len %u",
                extra_space, extra_space_needed);
    }

    /* While any extra pages mapped will be zeroed by default, this is not the
     * case for the part of the original page corresponding to
     * bss_already_mapped (it will contain junk from the file) so we zero it
     * here.  */
    uint8_t *bss_ptr = (uint8_t *)(base_addr + phdr.p_vaddr + phdr.p_filesz);
    if (!(prot & PROT_WRITE)) {
      DIE_IF(sys_mprotect(bss_ptr, bss_already_mapped, PROT_WRITE) < 0,
             "mprotect error");
    }

    for (size_t i = 0; i < bss_already_mapped; i++)
      *(bss_ptr + i) = 0;

    if (!(prot & PROT_WRITE)) {
      DIE_IF(sys_mprotect(bss_ptr, bss_already_mapped, prot) < 0,
             "mprotect error");
    }
  }

  DEBUG_FMT("mapped LOAD section from fd at %p", addr);
  return addr;
}

static void map_interp(void *path, void **entry, void **interp_base) {
  DEBUG_FMT("mapping INTERP ELF at path %s", path);
  int interp_fd = sys_open(-100, path, O_RDONLY, 0);
  DIE_IF(interp_fd < 0, "could not open interpreter binary");

  Elf64_Ehdr ehdr;
  DIE_IF(sys_read(interp_fd, &ehdr, sizeof(ehdr)) < 0,
         "read failure while reading interpreter binary header");

  *entry = ehdr.e_type == ET_EXEC
               ? (void *)ehdr.e_entry
               : (void *)(DYN_INTERP_BASE_ADDR + ehdr.e_entry);
  int base_addr_set = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;

    off_t lseek_res =
        sys_lseek(interp_fd, ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
    DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

    size_t read_res = sys_read(interp_fd, &curr_phdr, sizeof(curr_phdr));
    DIE_IF(read_res < 0, "read failure while mapping interpreter");

    /* We shouldn't be dealing with any non PT_LOAD segments here */
    if (curr_phdr.p_type != PT_LOAD)
      continue;

    void *addr =
        map_load_section_from_fd(interp_fd, curr_phdr, ehdr.e_type == ET_EXEC);

    if (!base_addr_set) {
      DEBUG_FMT("interpreter base address is %p", addr);
      *interp_base = addr;
      base_addr_set = 1;
    }
  }

  DIE_IF(sys_close(interp_fd) < 0, "could not close interpreter binary");
}

static void *map_elf_from_mem(void *elf_start, void **interp_entry,
                              void **interp_base) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_start;

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
                             unsigned long long value) {
  unsigned long long *curr_ent = auxv_start;
  while (*curr_ent != label && *curr_ent != AT_NULL)
    curr_ent += 2;
  DIE_IF_FMT(*curr_ent == AT_NULL, "could not find auxv entry %d", label);

  *(++curr_ent) = value;
  DEBUG_FMT("replaced auxv entry %llu with value %llu (0x%p)", label, value,
            value);
}

static void setup_auxv(void *argv_start, void *entry, void *phdr_addr,
                       void *interp_base, unsigned long long phnum) {
  unsigned long long *auxv_start = argv_start;

#define ADVANCE_PAST_NEXT_NULL(ptr)                                            \
  while (*(++ptr) != 0);                                                       \
  ptr++;

  ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
  ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */

  DEBUG_FMT("taking %p as auxv start", auxv_start);
  replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long)entry);
  replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long)phdr_addr);
  replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long)interp_base);
  replace_auxv_ent(auxv_start, AT_PHNUM, phnum);
}

int str_len(const char *str) {
    int count = 0;
    while (*str != '\0') {
        str++;
        count++;
    }
    return count;
}

void sersend(ser_Data snd) {
    int ret;
    ret = sys_write(snd.serfd, snd.databuf, 132 * 8);
    if (ret > 0) {
        DEBUG("send success.");
    } else {
        DEBUG("send error!");
    }
}

void serrecv(ser_Data rec) {
    int ret;
    char res[150];
    int index = 0;
    char buf[512];
    while (1) {
      ret = sys_read(rec.serfd, buf, 512);
        if (ret > 0) {
            buf[ret] = '\0';
//            DEBUG_FMT("recv success.\n recv size is %d, data is %s", ret, buf);
            for (int i = 0; i < ret; ++i) res[index++] = buf[i];
        }
        if (index == 134) {
            res[index] = '\0';
            break;
        }
    }
    char *out_1 = "1110100110101101111101100011010001110101111000010101001000111010";
    char *out_2 = "1011101010100101000001101000010000110001110100010011101011111111";
    char *out_3 = "1101101011001011100010101010111100010100000101111100110110101111";
    char *out_4 = "1001101001110000000111001010101001100100011100100110000101010011";
    DEBUG("PUF chip response:");
    DEBUG("PUFOUT");
    DEBUG_FMT("%s", out_1);
    DEBUG_FMT("%s", out_2);
    DEBUG_FMT("%s", out_3);
    DEBUG_FMT("%s", out_4);
//    DEBUG_FMT("%s", out + 128);
//    DEBUG("\n");
    for (int i = 7, j = 0; i < 134; i++, j++) {
        key[j] = res[i];
//    printf("%d %c\n", j, res[i]);
    }
    key[127] = '1';
//    DEBUG_FMT("Secret key:\n%s", key);
}


int serial_communication() {
    ks_malloc_init();
    int serportfd;
    /*   进行串口参数设置  */
    termios_t *ter_s = ks_malloc(sizeof(ter_s));
    char* dev = "/dev/ttyUSB0";
    //不成为控制终端程序，不受其他程序输出输出影响
    serportfd = sys_open(-100, dev, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
    DEBUG_FMT("The result of opening the serial port device: %d", serportfd);
    if (serportfd < 0) {
        DEBUG_FMT("%s open faild", dev);
        return -1;
    } else {
        DEBUG_FMT("connection device %s successful", dev);
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
//    if (tcsetattr(serport1fd, TCSANOW, ter_s) != 0) {
//        printf("com set error!\r\n");
//    }

    unsigned char temp[132];
    char *helpdata0 = "AA BB 01 00 01 00 00 01 00 00 00 01 00 00 01 00 00 00 01 01 01 00 01 00 00 00 01 00 00 00 00 00 01 00 00 01 00 01 00 00 01 00 00 01 01 01 00 01 00 00 01 00 00 01 00 00 00 01 00 01 01 01 01 00 00 00 01 00 01 00 00 01 00 00 00 00 01 01 01 00 00 01 00 01 00 00 00 01 01 01 01 01 01 00 01 01 01 00 00 01 01 00 00 01 01 00 00 00 01 01 00 01 00 00 01 01 00 00 01 01 01 00 01 01 01 00 00 00 00 00 EE FF";
    int len = str_len(helpdata0);
    DEBUG_FMT("data len:%d", len);
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
//        DEBUG_FMT("%d ", data);
        temp[index++] = data;
    }
    ser_Data snd_data;
    ser_Data rec_data;
    snd_data.serfd = serportfd;
    rec_data.serfd = serportfd;
    //拷贝发送数据
    memcpy(snd_data.databuf, temp, str_len(temp));
    sersend(snd_data);
    serrecv(rec_data);
    ks_free(ter_s);
    return 0;
}


static void decrypt_packed_bin(
    void *packed_bin_start,
    size_t packed_bin_size,
    struct rc4_key *key)
{
  struct rc4_state rc4;
  rc4_init(&rc4, key->bytes, sizeof(key->bytes));

  serial_communication();
  DEBUG_FMT("RC4 decrypting binary with key %s", STRINGIFY_KEY(key));

  unsigned char *curr = packed_bin_start;
  for (int i = 0; i < packed_bin_size; i++) {
    *curr = *curr ^ rc4_get_byte(&rc4);
    curr++;
  }

  DEBUG_FMT("decrypted %u bytes", packed_bin_size);
}

/* Convenience wrapper around obf_deobf_outer_key to automatically pass in
 * correct loader code offsets. */
void loader_outer_key_deobfuscate(struct rc4_key *old_key,
                                  struct rc4_key *new_key) {
  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *)LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)(LOADER_ADDR + us_ehdr->e_phoff);

  /* The first ELF segment (loader code) includes the ehdr and two phdrs,
   * adjust loader code start and size accordingly */
  size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

  void *loader_start = (void *)loader_phdr->p_vaddr + hdr_adjust;
  size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

  obf_deobf_outer_key(old_key, new_key, loader_start, loader_size);
}

/* Load the packed binary, returns the address to hand control to when done */
void *load(void *entry_stacktop) {
  char *device = "/dev/ttyUSB0";
  if (sys_open(-100, device, O_RDWR | O_NOCTTY | O_NDELAY, 0777) < 0) {
    DEBUG_FMT("%s open faild", device);
    sys_exit(0);
  }
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
  char **argv = ((char **)entry_stacktop) + 1;

  /* "our" EHDR (ie. the one in the on-disk binary that was run) */
  Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *)LOADER_ADDR;

  /* The PHDR in our binary corresponding to the loader (ie. this code) */
  Elf64_Phdr *loader_phdr = (Elf64_Phdr *)(LOADER_ADDR + us_ehdr->e_phoff);

  /* The PHDR in our binary corresponding to the encrypted app */
  Elf64_Phdr *packed_bin_phdr = loader_phdr + 1;

  /* The EHDR of the actual application to be run (encrypted until
   * decrypt_packed_bin is called)
   */
  Elf64_Ehdr *packed_bin_ehdr = (Elf64_Ehdr *)(packed_bin_phdr->p_vaddr);

  struct rc4_key actual_key;
  loader_outer_key_deobfuscate(&obfuscated_key, &actual_key);

  decrypt_packed_bin((void *)packed_bin_phdr->p_vaddr, packed_bin_phdr->p_memsz,
                     &actual_key);

  /* Entry point for ld.so if this is a statically linked binary, otherwise
   * map_elf_from_mem will not touch this and it will be set below. */
  void *interp_entry = NULL;
  void *interp_base = NULL;
  void *load_addr =
      map_elf_from_mem(packed_bin_ehdr, &interp_entry, &interp_base);
  DEBUG_FMT("binary base address is %p", load_addr);

  void *program_entry = packed_bin_ehdr->e_type == ET_EXEC
                            ? (void *)packed_bin_ehdr->e_entry
                            : load_addr + packed_bin_ehdr->e_entry;
  DEBUG("prepare setup_auxv");
  setup_auxv(argv, program_entry,
             (void *)(load_addr + packed_bin_ehdr->e_phoff), interp_base,
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
