#include "loader/include/syscalls.h"
#include "loader/include/types.h"

ssize_t sys_write(int fd, const char *s, size_t count)
{
  ssize_t ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #64 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(fd),[val1]"r"(s),[val2]"r"(count)
  );
  return ret;
}

ssize_t sys_read(int fd, void *buf, size_t count)
{
  ssize_t ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #63 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(fd),[val1]"r"(buf),[val2]"r"(count)
  );

  return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
  off_t ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #62 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(fd),[val1]"r"(offset),[val2]"r"(whence)
  );

  return ret;
}

int sys_open(int dirfd, const char *pathname, int flags, int mode)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, %[val3]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #56 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(dirfd),[val1]"r"(pathname),[val2]"r"(flags),[val3]"r"(mode)
  );

  return ret;
}

int sys_close(int fd)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #57 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(fd)
  );

  return ret;
}

void sys_exit(int status)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #93 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(status)
  );

  /* Required so GCC accepts __attribute__((noreturn)) on this function */
  while(1) {}
}
// parameter & return value
// long long int sys_mmap(long long *addr, int length, int prot, int flags, int fd, int offset)
void *sys_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
  void *ret = NULL;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, %[val3]\n"
      "mov x4, %[val4]\n"
      "mov x5, %[val5]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #222 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(addr),[val1]"r"(length),[val2]"r"(prot),[val3]"r"(flags),[val4]"r"(fd),[val5]"r"(offset)
  );

  return ret;
}

// parameter
// int sys_munmap(long long int addr, size_t length)
int sys_munmap(void *addr, size_t length)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #215 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(addr),[val1]"r"(length)
  );

  return ret;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #226 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(addr),[val1]"r"(len),[val2]"r"(prot)
  );

  return ret;
}

long sys_ptrace(
    enum __ptrace_request request,
    pid_t pid,
    void *addr,
    void *data)
{
  long ret = 0;

  /* Note that the raw kernel-level ptrace interface differs from the one
   * exposed by glibc with regards to the PTRACE_PEEK requests. Glibc *returns*
   * the data, while the kernel-level interface stores it in *data.
   *
   * This function exposes the kernel-level interface.
   */
  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, %[val3]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #117 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(request),[val1]"r"(pid),[val2]"r"(addr),[val3]"r"(data)
  );

  return ret;
}

pid_t sys_wait4(pid_t pid, int *wstatus, int options)
{
  pid_t ret = 0;

  /* We pass NULL for rusage to simpify the function signature (no need for
   * that parameter currently)
   */
  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, #0\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #260 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(pid),[val1]"r"(wstatus),[val2]"r"(options)
  );

  return ret;
}

pid_t sys_fork()
{
  pid_t ret = 0;

  asm volatile(
      "mov x0, #0x11\n"
      "mov x1, #0x0\n"
      "mov x2, #0x0\n"
      "mov x3, #0x0\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #220 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
  );

  return ret;
}

int sys_kill(pid_t pid, int sig)
{
  pid_t ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #129 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(pid),[val1]"r"(sig)
  );

  return ret;
}

int sys_tgkill(pid_t tgid, pid_t tid, int sig)
{
  pid_t ret = 0;

  asm volatile(
        "mov x0, %[val0]\n"
        "mov x1, %[val1]\n"
        "mov x2, %[val2]\n"
        "stp x29, x30, [sp, -16]!\n"
        "mov x8, #131 \n"
        "svc #0 \n"
        "ldp x29, x30, [sp], 16\n"
        "mov %[result], x0"
        :[result]"=r"(ret)
        :[val0]"r"(tgid),[val1]"r"(tid),[val2]"r"(sig)
    );

  return ret;
}

pid_t sys_getpid()
{
  pid_t ret = 0;

  asm volatile(
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #172 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
  );

  return ret;
}

int sys_rt_sigaction(
    int sig,
    const struct kernel_sigaction *act,
    const struct kernel_sigaction *oact)
{
  int ret = 0;
  size_t sigsetsize = sizeof(act->sa_mask);

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #134 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(sig),[val1]"r"(act),[val2]"r"(oact)
  );

  return ret;
}

int sys_prctl(
    int option,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, %[val3]\n"
      "mov x4, %[val4]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #167 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(option),[val1]"r"(arg2),[val2]"r"(arg3),[val3]"r"(arg4),[val4]"r"(arg5)
  );

  return ret;
}

//int sys_stat(const char *pathname, struct stat *statbuf)
int sys_stat(int dirfd, const char *pathname, int flags, unsigned int mask, struct stat *statbuf)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "mov x2, %[val2]\n"
      "mov x3, %[val3]\n"
      "mov x4, %[val4]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #222 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(dirfd),[val1]"r"(pathname),[val2]"r"(flags),[val3]"r"(mask),[val4]"r"(statbuf)
  );

  return ret;
}

int sys_setrlimit(int resource, struct rlimit *rlim)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "mov x1, %[val1]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #164 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(resource),[val1]"r"(rlim)
  );

  return ret;
}

// malloc
char memory[2000];
struct block {
    //区块大小
    size_t size;
    //是否已使用
    int free;
    //指向下一个区块
    struct block *next;
};

struct block *freeList = (void *) memory;

void malloc_init() {
    freeList->size = 2000 - sizeof(struct block);  //可用空间大小
    freeList->free = 1;                        //1：空闲 0：使用
    freeList->next = NULL;                      //指向空
}

void malloc_split(struct block *fitting_slot, size_t size) {
    struct block *new = (void *) (fitting_slot + size + sizeof(struct block));          //定义new的地址
    new->size = (fitting_slot->size) - size - sizeof(struct block);                   //定义size大小
    new->free = 1;                                                                //设置是否工作
    new->next = fitting_slot->next;                                               //独立出去，形成新的块
    fitting_slot->size = size;
    fitting_slot->free = 0;
    fitting_slot->next = new;
}

void* malloc(size_t size) {
    struct block *curr, *prev;
    void *result;
    if (!(freeList->size)) malloc_init();
    curr = freeList;
    while (((curr->size < size) || (curr->free == 0)) && (curr->next != NULL)) {
        prev = curr;
        curr = curr->next;
    }
    if (curr->size == size) {
        curr->free = 0;
        result = (void *) (++curr);
        return result;
    } else if (curr->size > size + sizeof(struct block)) {            //所需要的内存大小小于区块大小
        malloc_split(curr, size);                            //分割区块函数
        result = (void *) (++curr);                                   //使用的位置
        return result;
    } else {
        result = NULL;
        return result;
    }
}


void malloc_merge() {
    struct block *curr, *prev;
    curr = freeList;
    while (curr != NULL && curr->next != NULL) {
        if (curr->free && curr->next->free) {
            curr->size += (curr->next->size) + sizeof(struct block);
            curr->next = curr->next->next;
        }
        prev = curr;
        curr = curr->next;
    }
}

void free(void *ptr) {
    if (((void *) memory <= ptr) && (ptr <= (void *) (memory + 2000))) {
        struct block *curr = ptr;
        curr--;
        curr->free = 1;
        malloc_merge();
    } else
        return;
}


