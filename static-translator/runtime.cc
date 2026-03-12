#include "runtime.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// --- AddressMap ---

void AddressMap::add(uint64_t guest_addr, TranslatedFuncPtr func) {
    map_[guest_addr] = func;
}

TranslatedFuncPtr AddressMap::lookup(uint64_t guest_addr) const {
    auto it = map_.find(guest_addr);
    if (it != map_.end())
        return it->second;
    return nullptr;
}

// --- CPU State Init ---

void aot_init_cpu(AotCpuState* cpu, uint64_t entry_addr,
                  uint64_t stack_top) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->self = cpu;
    cpu->state = nullptr;

    // Set RIP to entry point
    cpu_reg(cpu, X86Reg::RIP) = entry_addr;
    // Set RSP to top of stack
    cpu_reg(cpu, X86Reg::RSP) = stack_top;
    // Zero all other GPRs (already done by memset)
}

// --- Dispatch Loop ---
// The CDECL translated functions have signature:
//   void func(uint8_t* sptr)
// where sptr = &cpu->regdata[0]
//
// Each function reads RIP at entry, executes the basic block(s),
// and writes the new RIP before returning. The dispatch loop
// reads the new RIP and calls the next function.

void aot_dispatch_loop(AotCpuState* cpu, const AddressMap& map) {
    uint8_t* sptr = cpu->regdata;

    for (;;) {
        uint64_t pc = cpu_reg(cpu, X86Reg::RIP);

        TranslatedFuncPtr fn = map.lookup(pc);
        if (!fn) {
            fprintf(stderr, "aot-runtime: no translation for address 0x%lx\n",
                    (unsigned long)pc);
            fprintf(stderr, "  RAX=0x%lx RDI=0x%lx RSI=0x%lx RSP=0x%lx\n",
                    (unsigned long)cpu_reg(cpu, X86Reg::RAX),
                    (unsigned long)cpu_reg(cpu, X86Reg::RDI),
                    (unsigned long)cpu_reg(cpu, X86Reg::RSI),
                    (unsigned long)cpu_reg(cpu, X86Reg::RSP));
            _exit(127);
        }

        fn(sptr);
    }
}

void aot_print_address_map(const AddressMap& map) {
    printf("\n--- Address Map (%zu entries) ---\n", map.size());
}
