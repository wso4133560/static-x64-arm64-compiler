#include "elf-input.h"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

bool ElfInput::load(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    file_data_.resize(st.st_size);
    ssize_t nread = 0;
    while (nread < st.st_size) {
        ssize_t r = read(fd, file_data_.data() + nread, st.st_size - nread);
        if (r <= 0) {
            close(fd);
            return false;
        }
        nread += r;
    }
    close(fd);

    if (file_data_.size() < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "error: file too small for ELF header\n");
        return false;
    }

    memcpy(&ehdr_, file_data_.data(), sizeof(ehdr_));

    if (memcmp(ehdr_.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "error: not an ELF file\n");
        return false;
    }
    if (ehdr_.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "error: not a 64-bit ELF\n");
        return false;
    }
    if (ehdr_.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "error: not little-endian\n");
        return false;
    }

    if (!parse_segments()) return false;
    if (!parse_sections()) return false;
    if (!parse_symbols()) return false;

    return true;
}

bool ElfInput::parse_segments() {
    segments_.reserve(ehdr_.e_phnum);
    for (int i = 0; i < ehdr_.e_phnum; i++) {
        size_t off = ehdr_.e_phoff + i * ehdr_.e_phentsize;
        if (off + sizeof(Elf64_Phdr) > file_data_.size()) return false;

        Elf64_Phdr phdr;
        memcpy(&phdr, file_data_.data() + off, sizeof(phdr));

        ElfSegment seg;
        seg.type = phdr.p_type;
        seg.flags = phdr.p_flags;
        seg.offset = phdr.p_offset;
        seg.vaddr = phdr.p_vaddr;
        seg.paddr = phdr.p_paddr;
        seg.filesz = phdr.p_filesz;
        seg.memsz = phdr.p_memsz;
        seg.align = phdr.p_align;
        segments_.push_back(seg);
    }
    return true;
}

bool ElfInput::parse_sections() {
    sections_.reserve(ehdr_.e_shnum);
    // Read section header string table index
    uint16_t shstrndx = ehdr_.e_shstrndx;
    uint64_t shstrtab_offset = 0;

    if (shstrndx < ehdr_.e_shnum) {
        size_t off = ehdr_.e_shoff + shstrndx * ehdr_.e_shentsize;
        if (off + sizeof(Elf64_Shdr) <= file_data_.size()) {
            Elf64_Shdr shdr;
            memcpy(&shdr, file_data_.data() + off, sizeof(shdr));
            shstrtab_offset = shdr.sh_offset;
        }
    }

    for (int i = 0; i < ehdr_.e_shnum; i++) {
        size_t off = ehdr_.e_shoff + i * ehdr_.e_shentsize;
        if (off + sizeof(Elf64_Shdr) > file_data_.size()) return false;

        Elf64_Shdr shdr;
        memcpy(&shdr, file_data_.data() + off, sizeof(shdr));

        std::string name;
        if (shstrtab_offset && shdr.sh_name)
            name = read_string(shstrtab_offset, shdr.sh_name);

        ElfSection section;
        section.name = std::move(name);
        section.type = shdr.sh_type;
        section.flags = shdr.sh_flags;
        section.addr = shdr.sh_addr;
        section.offset = shdr.sh_offset;
        section.size = shdr.sh_size;
        section.entsize = shdr.sh_entsize;
        sections_.push_back(std::move(section));
    }
    return true;
}

bool ElfInput::parse_symbols() {
    for (const auto& sec : sections_) {
        if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM)
            continue;
        if (sec.entsize < sizeof(Elf64_Sym))
            continue;

        // Find associated string table
        // The string table index is stored in sh_link of the symbol section.
        // We need to re-read the section header to get sh_link.
        size_t sec_idx = &sec - sections_.data();
        size_t shdr_off = ehdr_.e_shoff + sec_idx * ehdr_.e_shentsize;
        Elf64_Shdr shdr;
        memcpy(&shdr, file_data_.data() + shdr_off, sizeof(shdr));

        uint64_t strtab_offset = 0;
        if (shdr.sh_link < sections_.size())
            strtab_offset = sections_[shdr.sh_link].offset;

        size_t count = sec.size / sec.entsize;
        for (size_t i = 0; i < count; i++) {
            size_t off = sec.offset + i * sec.entsize;
            if (off + sizeof(Elf64_Sym) > file_data_.size()) break;

            Elf64_Sym sym;
            memcpy(&sym, file_data_.data() + off, sizeof(sym));

            std::string name;
            if (strtab_offset && sym.st_name)
                name = read_string(strtab_offset, sym.st_name);

            ElfSymbol esym;
            esym.name = std::move(name);
            esym.addr = sym.st_value;
            esym.size = sym.st_size;
            esym.type = static_cast<uint8_t>(ELF64_ST_TYPE(sym.st_info));
            esym.bind = static_cast<uint8_t>(ELF64_ST_BIND(sym.st_info));
            esym.shndx = sym.st_shndx;
            symbols_.push_back(std::move(esym));
        }
    }
    return true;
}

std::string ElfInput::read_string(uint64_t strtab_offset, uint64_t str_offset) const {
    size_t pos = strtab_offset + str_offset;
    if (pos >= file_data_.size()) return "";
    const char* s = reinterpret_cast<const char*>(file_data_.data() + pos);
    size_t max_len = file_data_.size() - pos;
    size_t len = strnlen(s, max_len);
    return std::string(s, len);
}

size_t ElfInput::read_vaddr(uint64_t vaddr, uint8_t* buf, size_t len) const {
    for (const auto& seg : segments_) {
        if (seg.type != PT_LOAD) continue;
        if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz) {
            uint64_t offset = seg.offset + (vaddr - seg.vaddr);
            size_t avail = seg.filesz - (vaddr - seg.vaddr);
            size_t to_read = len < avail ? len : avail;
            if (offset + to_read > file_data_.size()) return 0;
            memcpy(buf, file_data_.data() + offset, to_read);
            return to_read;
        }
    }
    return 0;
}

const ElfSection* ElfInput::find_section(const char* name) const {
    for (const auto& sec : sections_)
        if (sec.name == name)
            return &sec;
    return nullptr;
}

std::vector<const ElfSymbol*> ElfInput::function_symbols() const {
    std::vector<const ElfSymbol*> result;
    for (const auto& sym : symbols_) {
        if (sym.addr == 0 || sym.shndx == SHN_UNDEF)
            continue;
        // Include STT_FUNC and global/weak STT_NOTYPE symbols in code sections
        if (sym.type == STT_FUNC) {
            result.push_back(&sym);
        } else if (sym.type == STT_NOTYPE &&
                   (sym.bind == STB_GLOBAL || sym.bind == STB_WEAK)) {
            // Check if the symbol points into an executable segment
            for (const auto& seg : segments_) {
                if (seg.type == PT_LOAD && (seg.flags & PF_X) &&
                    sym.addr >= seg.vaddr &&
                    sym.addr < seg.vaddr + seg.memsz) {
                    result.push_back(&sym);
                    break;
                }
            }
        }
    }
    return result;
}

static const char* elf_machine_name(uint16_t machine) {
    switch (machine) {
    case EM_X86_64: return "x86-64";
    case EM_AARCH64: return "AArch64";
    case EM_RISCV: return "RISC-V";
    default: return "unknown";
    }
}

static const char* elf_type_name(uint16_t type) {
    switch (type) {
    case ET_EXEC: return "EXEC";
    case ET_DYN: return "DYN (PIE)";
    case ET_REL: return "REL";
    default: return "unknown";
    }
}

static const char* phdr_type_name(uint32_t type) {
    switch (type) {
    case PT_LOAD: return "LOAD";
    case PT_DYNAMIC: return "DYNAMIC";
    case PT_INTERP: return "INTERP";
    case PT_NOTE: return "NOTE";
    case PT_PHDR: return "PHDR";
    case PT_TLS: return "TLS";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_STACK: return "GNU_STACK";
    case PT_GNU_RELRO: return "GNU_RELRO";
    default: return "OTHER";
    }
}

void ElfInput::print_info() const {
    printf("=== ELF Header ===\n");
    printf("  Type:         %s\n", elf_type_name(ehdr_.e_type));
    printf("  Machine:      %s (0x%x)\n", elf_machine_name(ehdr_.e_machine), ehdr_.e_machine);
    printf("  Entry point:  0x%lx\n", (unsigned long)ehdr_.e_entry);
    printf("  Sections:     %u\n", ehdr_.e_shnum);
    printf("  Segments:     %u\n", ehdr_.e_phnum);

    printf("\n=== Segments ===\n");
    printf("  %-16s %-8s %-18s %-18s %-10s %-10s\n",
           "Type", "Flags", "VAddr", "FileSize", "MemSize", "Align");
    for (const auto& seg : segments_) {
        char flags[4] = "---";
        if (seg.flags & PF_R) flags[0] = 'R';
        if (seg.flags & PF_W) flags[1] = 'W';
        if (seg.flags & PF_X) flags[2] = 'X';
        printf("  %-16s %-8s 0x%016lx 0x%08lx 0x%08lx 0x%lx\n",
               phdr_type_name(seg.type), flags,
               (unsigned long)seg.vaddr, (unsigned long)seg.filesz,
               (unsigned long)seg.memsz, (unsigned long)seg.align);
    }

    printf("\n=== Sections ===\n");
    printf("  %-20s %-12s %-18s %-10s\n", "Name", "Type", "Addr", "Size");
    for (const auto& sec : sections_) {
        if (sec.name.empty()) continue;
        const char* type_str = "OTHER";
        switch (sec.type) {
        case SHT_PROGBITS: type_str = "PROGBITS"; break;
        case SHT_SYMTAB: type_str = "SYMTAB"; break;
        case SHT_STRTAB: type_str = "STRTAB"; break;
        case SHT_RELA: type_str = "RELA"; break;
        case SHT_NOBITS: type_str = "NOBITS"; break;
        case SHT_NOTE: type_str = "NOTE"; break;
        case SHT_DYNSYM: type_str = "DYNSYM"; break;
        }
        printf("  %-20s %-12s 0x%016lx 0x%lx\n",
               sec.name.c_str(), type_str,
               (unsigned long)sec.addr, (unsigned long)sec.size);
    }

    auto funcs = function_symbols();
    printf("\n=== Function Symbols (%zu) ===\n", funcs.size());
    if (funcs.size() <= 50) {
        for (const auto* sym : funcs) {
            printf("  0x%016lx  size=%-6lu  %s\n",
                   (unsigned long)sym->addr, (unsigned long)sym->size,
                   sym->name.empty() ? "<unnamed>" : sym->name.c_str());
        }
    } else {
        for (size_t i = 0; i < 20; i++) {
            printf("  0x%016lx  size=%-6lu  %s\n",
                   (unsigned long)funcs[i]->addr, (unsigned long)funcs[i]->size,
                   funcs[i]->name.empty() ? "<unnamed>" : funcs[i]->name.c_str());
        }
        printf("  ... (%zu more)\n", funcs.size() - 20);
    }
}
