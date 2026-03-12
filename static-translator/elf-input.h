#ifndef _INSTREW_STATIC_ELF_INPUT_H
#define _INSTREW_STATIC_ELF_INPUT_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <elf.h>

struct ElfSymbol {
    std::string name;
    uint64_t addr;
    uint64_t size;
    uint8_t type;   // STT_FUNC, STT_OBJECT, etc.
    uint8_t bind;   // STB_LOCAL, STB_GLOBAL, etc.
    uint16_t shndx;
};

struct ElfSection {
    std::string name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint64_t entsize;
};

struct ElfSegment {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

class ElfInput {
public:
    bool load(const char* path);
    void print_info() const;

    uint16_t machine() const { return ehdr_.e_machine; }
    uint16_t type() const { return ehdr_.e_type; }
    uint64_t entry() const { return ehdr_.e_entry; }

    const std::vector<ElfSection>& sections() const { return sections_; }
    const std::vector<ElfSegment>& segments() const { return segments_; }
    const std::vector<ElfSymbol>& symbols() const { return symbols_; }

    // Read raw bytes from the file at a given virtual address.
    // Returns number of bytes read, or 0 on failure.
    size_t read_vaddr(uint64_t vaddr, uint8_t* buf, size_t len) const;

    // Get pointer to raw file data at offset.
    const uint8_t* file_data() const { return file_data_.data(); }
    size_t file_size() const { return file_data_.size(); }

    // Find section by name.
    const ElfSection* find_section(const char* name) const;

    // Get all function symbols (STT_FUNC with nonzero address).
    std::vector<const ElfSymbol*> function_symbols() const;

private:
    Elf64_Ehdr ehdr_{};
    std::vector<ElfSection> sections_;
    std::vector<ElfSegment> segments_;
    std::vector<ElfSymbol> symbols_;
    std::vector<uint8_t> file_data_;

    bool parse_sections();
    bool parse_segments();
    bool parse_symbols();
    std::string read_string(uint64_t strtab_offset, uint64_t str_offset) const;
};

#endif
