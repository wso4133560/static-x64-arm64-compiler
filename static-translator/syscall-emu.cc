#include "runtime.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifdef AOT_STANDALONE
extern "C" void aot_write_stderr(const char* msg, unsigned long len);
#endif

// x86-64 syscall ABI:
//   nr=RAX, arg0=RDI, arg1=RSI, arg2=RDX, arg3=R10, arg4=R8, arg5=R9
//   return in RAX
// Rellume register offsets (bytes):
//   RAX=8, RCX=16, RDX=24, RSI=56, RDI=64, R8=72, R9=80, R10=88, R11=96

#ifdef AOT_STANDALONE
// Raw aarch64 syscall — avoids referencing libc's syscall() which would
// conflict with the 'syscall' symbol defined in glue.S for translated code.
static long do_syscall6(long nr, long a0, long a1, long a2,
                        long a3, long a4, long a5) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
        : "=r"(x0)
        : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}
#else
static long do_syscall6(long nr, long a0, long a1, long a2,
                        long a3, long a4, long a5) {
    return syscall(nr, a0, a1, a2, a3, a4, a5);
}
#endif

extern "C" void aot_syscall(uint8_t* regs) {
    auto reg = [regs](unsigned off) -> uint64_t& {
        return *reinterpret_cast<uint64_t*>(regs + off);
    };

    uint64_t nr   = reg(X86Reg::RAX);
    uint64_t arg0 = reg(X86Reg::RDI);
    uint64_t arg1 = reg(X86Reg::RSI);
    uint64_t arg2 = reg(X86Reg::RDX);
    uint64_t arg3 = reg(X86Reg::R10);
    uint64_t arg4 = reg(X86Reg::R8);
    uint64_t arg5 = reg(X86Reg::R9);

    long res = -ENOSYS;

    switch (nr) {
    // Direct passthrough — same semantics, just different syscall number
    case 0:   res = do_syscall6(__NR_read, arg0, arg1, arg2, 0, 0, 0); break;
    case 1:   res = do_syscall6(__NR_write, arg0, arg1, arg2, 0, 0, 0); break;
    case 3:   res = do_syscall6(__NR_close, arg0, 0, 0, 0, 0, 0); break;
    case 8:   res = do_syscall6(__NR_lseek, arg0, arg1, arg2, 0, 0, 0); break;
    case 9:   res = do_syscall6(__NR_mmap, arg0, arg1, arg2, arg3, arg4, arg5); break;
    case 10:  res = do_syscall6(__NR_mprotect, arg0, arg1, arg2, 0, 0, 0); break;
    case 11:  res = do_syscall6(__NR_munmap, arg0, arg1, 0, 0, 0, 0); break;
    case 12:  res = do_syscall6(__NR_brk, arg0, 0, 0, 0, 0, 0); break;
    case 16:  res = do_syscall6(__NR_ioctl, arg0, arg1, arg2, 0, 0, 0); break;
    case 17:  res = do_syscall6(__NR_pread64, arg0, arg1, arg2, arg3, 0, 0); break;
    case 18:  res = do_syscall6(__NR_pwrite64, arg0, arg1, arg2, arg3, 0, 0); break;
    case 19:  res = do_syscall6(__NR_readv, arg0, arg1, arg2, 0, 0, 0); break;
    case 20:  res = do_syscall6(__NR_writev, arg0, arg1, arg2, 0, 0, 0); break;
    case 24:  res = do_syscall6(__NR_sched_yield, 0, 0, 0, 0, 0, 0); break;
    case 25:  res = do_syscall6(__NR_mremap, arg0, arg1, arg2, arg3, arg4, 0); break;
    case 28:  res = do_syscall6(__NR_madvise, arg0, arg1, arg2, 0, 0, 0); break;
    case 32:  res = do_syscall6(__NR_dup, arg0, 0, 0, 0, 0, 0); break;
    case 39:  res = do_syscall6(__NR_getpid, 0, 0, 0, 0, 0, 0); break;
    case 41:  res = do_syscall6(__NR_socket, arg0, arg1, arg2, 0, 0, 0); break;
    case 42:  res = do_syscall6(__NR_connect, arg0, arg1, arg2, 0, 0, 0); break;
    case 59:  res = do_syscall6(__NR_execve, arg0, arg1, arg2, 0, 0, 0); break;
    case 60:  // exit
        _exit(static_cast<int>(arg0));
        __builtin_unreachable();
    case 61:  res = do_syscall6(__NR_wait4, arg0, arg1, arg2, arg3, 0, 0); break;
    case 63:  res = do_syscall6(__NR_uname, arg0, 0, 0, 0, 0, 0); break;
    case 79:  res = do_syscall6(__NR_getcwd, arg0, arg1, 0, 0, 0, 0); break;
    case 80:  res = do_syscall6(__NR_chdir, arg0, 0, 0, 0, 0, 0); break;
    case 96:  res = do_syscall6(__NR_gettimeofday, arg0, arg1, 0, 0, 0, 0); break;
    case 97:  res = do_syscall6(__NR_getrlimit, arg0, arg1, 0, 0, 0, 0); break;
    case 99:  res = do_syscall6(__NR_sysinfo, arg0, 0, 0, 0, 0, 0); break;
    case 102: res = do_syscall6(__NR_getuid, 0, 0, 0, 0, 0, 0); break;
    case 104: res = do_syscall6(__NR_getgid, 0, 0, 0, 0, 0, 0); break;
    case 107: res = do_syscall6(__NR_geteuid, 0, 0, 0, 0, 0, 0); break;
    case 108: res = do_syscall6(__NR_getegid, 0, 0, 0, 0, 0, 0); break;
    case 110: res = do_syscall6(__NR_getppid, 0, 0, 0, 0, 0, 0); break;
    case 186: res = do_syscall6(__NR_gettid, 0, 0, 0, 0, 0, 0); break;
    case 202: res = do_syscall6(__NR_futex, arg0, arg1, arg2, arg3, arg4, arg5); break;
    case 217: res = do_syscall6(__NR_getdents64, arg0, arg1, arg2, 0, 0, 0); break;
    case 218: res = do_syscall6(__NR_set_tid_address, arg0, 0, 0, 0, 0, 0); break;
    case 228: res = do_syscall6(__NR_clock_gettime, arg0, arg1, 0, 0, 0, 0); break;
    case 229: res = do_syscall6(__NR_clock_getres, arg0, arg1, 0, 0, 0, 0); break;
    case 230: res = do_syscall6(__NR_clock_nanosleep, arg0, arg1, arg2, arg3, 0, 0); break;
    case 292: res = do_syscall6(__NR_dup3, arg0, arg1, arg2, 0, 0, 0); break;
    case 293: res = do_syscall6(__NR_pipe2, arg0, arg1, 0, 0, 0, 0); break;
    case 302: res = do_syscall6(__NR_prlimit64, arg0, arg1, arg2, arg3, 0, 0); break;
    case 318: res = do_syscall6(__NR_getrandom, arg0, arg1, arg2, 0, 0, 0); break;

    // Syscalls that need argument remapping
    case 2: // open → openat
        res = do_syscall6(__NR_openat, AT_FDCWD, arg0, arg1, arg2, 0, 0);
        break;
    case 21: // access → faccessat
        res = do_syscall6(__NR_faccessat, AT_FDCWD, arg0, arg1, 0, 0, 0);
        break;
    case 22: // pipe → pipe2
        res = do_syscall6(__NR_pipe2, arg0, 0, 0, 0, 0, 0);
        break;
    case 56: // clone (fork only — CLONE_VM not supported)
        res = do_syscall6(__NR_clone, arg0, arg1, arg2, arg4, arg3, 0);
        break;
    case 57: // fork
        res = do_syscall6(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
        break;
    case 82: // rename → renameat
        res = do_syscall6(__NR_renameat, AT_FDCWD, arg0, AT_FDCWD, arg1, 0, 0);
        break;
    case 83: // mkdir → mkdirat
        res = do_syscall6(__NR_mkdirat, AT_FDCWD, arg0, arg1, 0, 0, 0);
        break;
    case 87: // unlink → unlinkat
        res = do_syscall6(__NR_unlinkat, AT_FDCWD, arg0, 0, 0, 0, 0);
        break;
    case 89: // readlink → readlinkat
        res = do_syscall6(__NR_readlinkat, AT_FDCWD, arg0, arg1, arg2, 0, 0);
        break;
    case 257: // openat
        res = do_syscall6(__NR_openat, arg0, arg1, arg2, arg3, 0, 0);
        break;

    // arch_prctl — FS/GS base emulation
    case 158:
        switch (arg0) {
        case 0x1001: reg(X86Reg::GSBASE) = arg1; res = 0; break; // SET_GS
        case 0x1002: reg(X86Reg::FSBASE) = arg1; res = 0; break; // SET_FS
        default: res = -EINVAL; break;
        }
        break;

    // exit_group
    case 231:
        _exit(static_cast<int>(arg0));
        __builtin_unreachable();

    // Ignorable syscalls
    case 203: // sched_setaffinity
    case 204: // sched_getaffinity
    case 334: // rseq
        res = -ENOSYS;
        break;

    default:
#ifdef AOT_STANDALONE
        {
            const char msg[] = "aot-runtime: unhandled x86-64 syscall\n";
            aot_write_stderr(msg, sizeof(msg) - 1);
        }
#else
        fprintf(stderr, "aot-runtime: unhandled x86-64 syscall %lu "
                "(%lx %lx %lx %lx %lx %lx)\n",
                (unsigned long)nr,
                (unsigned long)arg0, (unsigned long)arg1,
                (unsigned long)arg2, (unsigned long)arg3,
                (unsigned long)arg4, (unsigned long)arg5);
#endif
        res = -ENOSYS;
        break;
    }

    // x86-64 syscall clobbers RCX and R11
    reg(X86Reg::RAX) = static_cast<uint64_t>(res);
    reg(X86Reg::RCX) = reg(X86Reg::RIP);  // RCX = return address
    reg(X86Reg::R11) = 0;                  // R11 = saved RFLAGS (simplified)
}
