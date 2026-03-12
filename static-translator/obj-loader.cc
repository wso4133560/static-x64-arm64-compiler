#include "obj-loader.h"

#include <cstdio>
#include <cstring>
#include <elf.h>
#include <map>
#include <sys/mman.h>

// AArch64 relocation types
#define R_AARCH64_CALL26            283
#define R_AARCH64_JUMP26            282
#define R_AARCH64_ADR_PREL_PG_HI21  275
#define R_AARCH64_ADD_ABS_LO12_NC   277
#define R_AARCH64_LDST64_ABS_LO12_NC 286

// Trampoline: 16 bytes per entry
//   LDR X16, [PC, #8]   ; 0x58000050
//   BR  X16              ; 0xD61F0200
//   .quad <target_addr>
struct Trampoline {
    uint32_t ldr_x16;   // LDR X16, #8
    uint32_t br_x16;    // BR X16
    uint64_t target;
};
static_assert(sizeof(Trampoline) == 16, "trampoline size");

static constexpr uint32_t LDR_X16_PC8 = 0x58000050;
static constexpr uint32_t BR_X16      = 0xD61F0200;
static constexpr size_t MAX_TRAMPOLINES = 64;

// Layout: [.text code ...] [trampoline pool ...]
// All in one mmap allocation.

static bool apply_reloc(uint8_t* code, uint64_t code_base,
                        unsigned type, uint64_t offset,
                        int64_t addend, uint64_t sym_addr) {
    uint32_t* patch = reinterpret_cast<uint32_t*>(code + offset);
    uint64_t P = code_base + offset;
    uint64_t S = sym_addr;
    int64_t A = addend;

    switch (type) {
    case R_AARCH64_CALL26:
    case R_AARCH64_JUMP26: {
        int64_t off = (S + A - P);
        if (off < -(1 << 27) || off >= (1 << 27))
            return false;  // caller should use trampoline
        uint32_t imm26 = (off >> 2) & 0x03FFFFFF;
        *patch = (*patch & 0xFC000000) | imm26;
        return true;
    }
    case R_AARCH64_ADR_PREL_PG_HI21: {
        int64_t pg = ((S + A) & ~0xFFFULL) - (P & ~0xFFFULL);
        uint32_t immlo = ((pg >> 12) & 0x3) << 29;
        uint32_t immhi = ((pg >> 14) & 0x7FFFF) << 5;
        *patch = (*patch & 0x9F00001F) | immlo | immhi;
        return true;
    }
    case R_AARCH64_ADD_ABS_LO12_NC: {
        uint32_t imm12 = ((S + A) & 0xFFF) << 10;
        *patch = (*patch & 0xFFC003FF) | imm12;
        return true;
    }
    case R_AARCH64_LDST64_ABS_LO12_NC: {
        uint32_t imm12 = (((S + A) & 0xFFF) >> 3) << 10;
        *patch = (*patch & 0xFFC003FF) | imm12;
        return true;
    }
    default:
        fprintf(stderr, "obj-loader: unsupported reloc type %u\n", type);
        return false;
    }
}

void* obj_load_func(const void* obj_data, size_t obj_size,
                    const SymbolResolver& resolver,
                    void** out_base, size_t* out_size) {
    if (obj_size < sizeof(Elf64_Ehdr))
        return nullptr;

    auto* ehdr = static_cast<const Elf64_Ehdr*>(obj_data);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return nullptr;
    if (ehdr->e_type != ET_REL)
        return nullptr;

    auto raw = static_cast<const uint8_t*>(obj_data);
    auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(
        raw + ehdr->e_shoff);

    const char* shstrtab = nullptr;
    if (ehdr->e_shstrndx < ehdr->e_shnum)
        shstrtab = reinterpret_cast<const char*>(
            raw + shdrs[ehdr->e_shstrndx].sh_offset);

    unsigned text_idx = 0;
    const Elf64_Shdr* text_shdr = nullptr;
    const Elf64_Shdr* symtab_shdr = nullptr;
    const char* strtab = nullptr;

    for (unsigned i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_PROGBITS &&
            (shdrs[i].sh_flags & SHF_EXECINSTR) &&
            shstrtab &&
            strcmp(shstrtab + shdrs[i].sh_name, ".text") == 0) {
            text_shdr = &shdrs[i];
            text_idx = i;
        }
        if (shdrs[i].sh_type == SHT_SYMTAB)
            symtab_shdr = &shdrs[i];
    }

    if (!text_shdr || text_shdr->sh_size == 0)
        return nullptr;

    if (symtab_shdr && symtab_shdr->sh_link < ehdr->e_shnum)
        strtab = reinterpret_cast<const char*>(
            raw + shdrs[symtab_shdr->sh_link].sh_offset);

    size_t text_size = text_shdr->sh_size;
    size_t tramp_size = MAX_TRAMPOLINES * sizeof(Trampoline);
    size_t page_size = 4096;
    size_t alloc_size = (text_size + tramp_size + page_size - 1)
                        & ~(page_size - 1);

    uint8_t* mem = static_cast<uint8_t*>(
        mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mem == MAP_FAILED)
        return nullptr;

    memcpy(mem, raw + text_shdr->sh_offset, text_size);
    uint64_t code_base = reinterpret_cast<uint64_t>(mem);

    // Trampoline pool starts right after .text (aligned to 16)
    size_t tramp_off = (text_size + 15) & ~15ULL;
    auto* tramp_pool = reinterpret_cast<Trampoline*>(mem + tramp_off);
    unsigned tramp_count = 0;
    // Cache: sym_addr → trampoline address
    std::map<uint64_t, uint64_t> tramp_cache;

    // Apply relocations
    if (symtab_shdr) {
        auto* syms = reinterpret_cast<const Elf64_Sym*>(
            raw + symtab_shdr->sh_offset);

        for (unsigned i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type != SHT_RELA)
                continue;
            if (shdrs[i].sh_info != text_idx)
                continue;

            auto* relas = reinterpret_cast<const Elf64_Rela*>(
                raw + shdrs[i].sh_offset);
            unsigned nrelas = shdrs[i].sh_size / sizeof(Elf64_Rela);

            for (unsigned j = 0; j < nrelas; j++) {
                unsigned sym_i = ELF64_R_SYM(relas[j].r_info);
                unsigned rtype = ELF64_R_TYPE(relas[j].r_info);
                const Elf64_Sym& sym = syms[sym_i];

                uint64_t sym_addr = 0;
                if (sym.st_shndx == SHN_UNDEF && strtab) {
                    std::string name(strtab + sym.st_name);
                    sym_addr = resolver(name);
                    if (!sym_addr) {
                        fprintf(stderr, "obj-loader: unresolved '%s'\n",
                                name.c_str());
                        munmap(mem, alloc_size);
                        return nullptr;
                    }
                } else if (sym.st_shndx == text_idx) {
                    sym_addr = code_base + sym.st_value;
                } else {
                    continue;
                }

                // Try direct relocation first
                if (apply_reloc(mem, code_base, rtype,
                                relas[j].r_offset, relas[j].r_addend,
                                sym_addr))
                    continue;

                // CALL26/JUMP26 out of range — use trampoline
                if (rtype == R_AARCH64_CALL26 ||
                    rtype == R_AARCH64_JUMP26) {
                    uint64_t tramp_addr;
                    auto it = tramp_cache.find(sym_addr);
                    if (it != tramp_cache.end()) {
                        tramp_addr = it->second;
                    } else {
                        if (tramp_count >= MAX_TRAMPOLINES) {
                            fprintf(stderr, "obj-loader: trampoline pool "
                                    "exhausted\n");
                            munmap(mem, alloc_size);
                            return nullptr;
                        }
                        auto& t = tramp_pool[tramp_count++];
                        t.ldr_x16 = LDR_X16_PC8;
                        t.br_x16 = BR_X16;
                        t.target = sym_addr + relas[j].r_addend;
                        tramp_addr = reinterpret_cast<uint64_t>(&t);
                        tramp_cache[sym_addr] = tramp_addr;
                    }
                    // Patch BL/B to point to trampoline (must be in range)
                    if (!apply_reloc(mem, code_base, rtype,
                                     relas[j].r_offset, 0, tramp_addr)) {
                        fprintf(stderr, "obj-loader: trampoline still out "
                                "of range\n");
                        munmap(mem, alloc_size);
                        return nullptr;
                    }
                    continue;
                }

                fprintf(stderr, "obj-loader: relocation failed type=%u\n",
                        rtype);
                munmap(mem, alloc_size);
                return nullptr;
            }
        }
    }

    // Make executable
    if (mprotect(mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, alloc_size);
        return nullptr;
    }
    __builtin___clear_cache(reinterpret_cast<char*>(mem),
                            reinterpret_cast<char*>(mem) + alloc_size);

    if (out_base) *out_base = mem;
    if (out_size) *out_size = alloc_size;

    // Find function entry
    void* func_addr = mem;
    if (symtab_shdr) {
        auto* syms = reinterpret_cast<const Elf64_Sym*>(
            raw + symtab_shdr->sh_offset);
        unsigned nsyms = symtab_shdr->sh_size / sizeof(Elf64_Sym);
        for (unsigned k = 0; k < nsyms; k++) {
            if (ELF64_ST_TYPE(syms[k].st_info) == STT_FUNC &&
                syms[k].st_shndx == text_idx) {
                func_addr = mem + syms[k].st_value;
                break;
            }
        }
    }

    return func_addr;
}
