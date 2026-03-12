#ifndef _INSTREW_STATIC_ANALYZER_H
#define _INSTREW_STATIC_ANALYZER_H

#include "elf-input.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct BasicBlock {
    uint64_t start;
    uint64_t end;          // exclusive: address of next instruction after block
    uint64_t func_addr;    // owning function start address

    // Successors
    std::vector<uint64_t> successors;
    bool has_indirect_branch;
    bool is_call;          // ends with a call (fall-through is implicit successor)
    bool is_ret;           // ends with ret
    bool is_syscall;       // contains syscall instruction
};

struct Function {
    uint64_t start;
    uint64_t end;          // highest address + instruction length
    std::string name;
    std::vector<uint64_t> blocks;  // sorted basic block start addresses
    bool has_indirect_jumps;
    bool from_symbol;      // discovered via symbol table (vs. call target)
};

struct AnalysisResult {
    std::map<uint64_t, BasicBlock> blocks;   // addr → BasicBlock
    std::map<uint64_t, Function> functions;  // addr → Function
    std::set<uint64_t> unresolved_indirects; // addresses of unresolved indirect jmp/call
    uint64_t text_start;
    uint64_t text_size;
    uint64_t bytes_covered;

    double coverage() const {
        return text_size > 0 ? (double)bytes_covered / text_size * 100.0 : 0.0;
    }

    void print_summary() const;
    void print_functions() const;
};

class Analyzer {
public:
    explicit Analyzer(const ElfInput& elf);

    // Run the full analysis pipeline
    AnalysisResult analyze();

private:
    const ElfInput& elf_;

    // Working state
    std::set<uint64_t> work_queue_;
    std::set<uint64_t> visited_;
    std::map<uint64_t, BasicBlock> blocks_;
    std::set<uint64_t> function_entries_;
    std::set<uint64_t> unresolved_;

    // Read instruction bytes from ELF at virtual address
    size_t read_code(uint64_t addr, uint8_t* buf, size_t len);

    // Recursive descent: decode basic block starting at addr
    void explore_block(uint64_t addr);

    // Seed initial addresses from entry point and symbol table
    void seed_addresses();

    // Build function boundaries from discovered blocks
    void build_functions(AnalysisResult& result);

    // Try to resolve jump table patterns
    void try_resolve_jump_table(uint64_t jmp_addr, uint64_t base_addr);
};

#endif
