.section .text
.global _start

_start:
  # Per the SysV ABI, the value of %rbp is undefined upon getting control from
  # the kernel and should be set to 0 manually to mark the deepest stack frame.
  # xor %ebp, %ebp

#ifdef USE_RUNTIME
  # Fork, starting the runtime in the parent process and returning in the child
  BL do_fork

  # We've now forked. The runtime is running in our parent and will not return.
  # here. Only the child will execute the code below.
#endif

  # Load function has the following signature
  # void load(void *entry_stacktop)
  # mov %rsp, %rdi # entry_stacktop
  MOV x0, sp
  BL load

  # Return value of load is the address of ld.so to jump to, store it
  # push %rax
  STR x0 , [sp]

#ifdef USE_RUNTIME
  # Binary has been mapped into memory, have the parent ptrace the child
  sub sp, sp, #32
  stp x29, x30, [sp, #16]
  BL child_start_ptrace
  ldp x29, x30, [sp, #16]
  add sp, sp, #32
#endif

  # The x86-64 SysV ABI specifies that %rdx contains the address of a function
  # to be registered by libc with atexit upon entry (or 0 to indicate no
  # function). In practice, Linux always sets this to 0 (see ELF_PLAT_INIT
  # macro in kernel sources) before handing control to userspace. This register
  # was probably clobbered by the calls to load/do_fork above, so zero it
  # before we jump to program entry so the libc doesn't register a garbage
  # address as an exit handler.
  # xor %edx, %edx

  # While we're at it, zero all the other non-privileged registers (besides
  # %rbx, which is holding the program entry point to jump to) that Linux
  # normally zeros before handing control to userspace. Unlike %rdx, this isn't
  # strictly necessary, but we'll do it anyways to make things as deterministic
  # as possible.

  LDR x0 , [sp]
  BLR x0