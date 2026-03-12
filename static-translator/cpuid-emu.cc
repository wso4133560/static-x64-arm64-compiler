#include "runtime.h"

// CPUID emulation for AOT mode.
// Returns {eax|(ecx<<32), edx|(ebx<<32)} matching Rellume's cpuinfo callback.
// Extracted from client/emulate.c emulate_cpuid().

extern "C" CpuidResult aot_cpuid(uint32_t leaf, uint32_t subleaf) {
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    if (leaf == 0) {
        eax = 7;              // max basic CPUID
        ebx = 0x756e6547;    // "Genu"
        edx = 0x49656e69;    // "ineI"
        ecx = 0x6c65746e;    // "ntel"
    } else if (leaf == 1) {
        eax = 0;
        ecx = 0x00400000;    // movbe
        edx = 0x07808141;    // pae+cmov+fxsr+sse+sse2+mmx+cx8+fpu
        ebx = 0;
    } else if (leaf == 2) {
        eax = 0x80000001;    // reserved (al=01)
        ecx = 0x000000ec;    // L3=24MiB/24w/64l
        edx = 0x80000000;    // reserved
        ebx = 0x80000000;    // reserved
    } else if (leaf == 7 && subleaf == 0) {
        eax = 0;
        ebx = 0x00002200;    // erms + deprecate fpu-cs/ds
        ecx = 0;
        edx = 0;
    }
    // All other leaves return zeros

    CpuidResult r;
    r.lo = (uint64_t)eax | ((uint64_t)ecx << 32);
    r.hi = (uint64_t)edx | ((uint64_t)ebx << 32);
    return r;
}
