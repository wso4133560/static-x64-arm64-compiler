#ifndef _INSTREW_AOT_RUNTIME_H
#define _INSTREW_AOT_RUNTIME_H

#include <cstddef>
#include <cstdint>
#include <map>

// x86-64 register offsets in Rellume's CPU struct (from cpustruct-x86_64.inc)
// These are byte offsets into the regdata[] array.
namespace X86Reg {
    constexpr unsigned RIP    = 0;
    constexpr unsigned RAX    = 8;
    constexpr unsigned RCX    = 16;
    constexpr unsigned RDX    = 24;
    constexpr unsigned RBX    = 32;
    constexpr unsigned RSP    = 40;
    constexpr unsigned RBP    = 48;
    constexpr unsigned RSI    = 56;
    constexpr unsigned RDI    = 64;
    constexpr unsigned R8     = 72;
    constexpr unsigned R9     = 80;
    constexpr unsigned R10    = 88;
    constexpr unsigned R11    = 96;
    constexpr unsigned R12    = 104;
    constexpr unsigned R13    = 112;
    constexpr unsigned R14    = 120;
    constexpr unsigned R15    = 128;
    constexpr unsigned FSBASE = 144;
    constexpr unsigned GSBASE = 152;
}

// Minimal CPU state for AOT runtime (matches client/state.h layout)
struct AotCpuState {
    AotCpuState* self;
    void* state;          // unused in AOT mode
    uintptr_t _unused[6];

    alignas(64) uint8_t regdata[0x400];  // register file

    // No quick_tlb needed — we use a static address map instead
};

static_assert(offsetof(AotCpuState, regdata) == 0x40,
              "regdata offset mismatch");

// Convenience accessors
inline uint64_t& cpu_reg(AotCpuState* cpu, unsigned byte_offset) {
    return *reinterpret_cast<uint64_t*>(cpu->regdata + byte_offset);
}

// Address map entry: maps guest x86-64 address → translated function pointer
// Translated functions have signature: void(uint8_t* sptr)
// where sptr points to regdata (in LLVM address space 1)
using TranslatedFuncPtr = void (*)(uint8_t*);

struct AddressMapEntry {
    uint64_t guest_addr;
    TranslatedFuncPtr func;
};

// The address map (populated by the linker / AOT tool)
class AddressMap {
public:
    void add(uint64_t guest_addr, TranslatedFuncPtr func);
    TranslatedFuncPtr lookup(uint64_t guest_addr) const;
    size_t size() const { return map_.size(); }

private:
    std::map<uint64_t, TranslatedFuncPtr> map_;
};

// Syscall emulation: translates x86-64 syscall to native
// cpu_regs points to regdata (same as Rellume's sptr)
extern "C" void aot_syscall(uint8_t* cpu_regs);

// CPUID emulation
struct CpuidResult {
    uint64_t lo;  // eax | (ecx << 32)
    uint64_t hi;  // edx | (ebx << 32)
};
extern "C" CpuidResult aot_cpuid(uint32_t leaf, uint32_t subleaf);

// Main dispatch loop
void aot_dispatch_loop(AotCpuState* cpu, const AddressMap& map);

// Initialize CPU state for program start
void aot_init_cpu(AotCpuState* cpu, uint64_t entry_addr,
                  uint64_t stack_top);

#endif
