#include "analyzer.h"

#include <fadec.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <queue>

// Helper: is this instruction type a conditional jump?
static bool is_cond_jump(unsigned type) {
    switch (type) {
    case FDI_JA: case FDI_JBE: case FDI_JC: case FDI_JCXZ:
    case FDI_JG: case FDI_JGE: case FDI_JL: case FDI_JLE:
    case FDI_JNC: case FDI_JNO: case FDI_JNP: case FDI_JNS:
    case FDI_JNZ: case FDI_JO: case FDI_JP: case FDI_JS:
    case FDI_JZ:
    case FDI_LOOP: case FDI_LOOPZ: case FDI_LOOPNZ:
        return true;
    default:
        return false;
    }
}

// Helper: extract direct branch target from instruction operand.
// When fd_decode is called with a real address, relative branches
// are resolved to FD_OT_IMM with the absolute target address.
// When called with address=0, they appear as FD_OT_OFF with a relative offset.
// We handle both cases.
static bool get_branch_target(const FdInstr* instr, uint64_t next_pc, uint64_t* target) {
    int op_type = FD_OP_TYPE(instr, 0);
    if (op_type == FD_OT_IMM) {
        // Absolute address (when fd_decode was given a real address)
        *target = (uint64_t)instr->imm;
        return true;
    }
    if (op_type == FD_OT_OFF) {
        // Relative offset (when fd_decode was given address=0)
        *target = next_pc + (int64_t)instr->imm;
        return true;
    }
    return false; // indirect (register or memory operand)
}

Analyzer::Analyzer(const ElfInput& elf) : elf_(elf) {}

size_t Analyzer::read_code(uint64_t addr, uint8_t* buf, size_t len) {
    return elf_.read_vaddr(addr, buf, len);
}

void Analyzer::seed_addresses() {
    // 1. Entry point
    function_entries_.insert(elf_.entry());
    work_queue_.insert(elf_.entry());

    // 2. All function symbols
    auto funcs = elf_.function_symbols();
    for (const auto* sym : funcs) {
        function_entries_.insert(sym->addr);
        work_queue_.insert(sym->addr);
    }

    // 3. Scan symbol table for any NOTYPE globals in executable segments
    for (const auto& sym : elf_.symbols()) {
        if (sym.addr == 0 || sym.shndx == SHN_UNDEF) continue;
        if (sym.type == STT_FUNC) {
            function_entries_.insert(sym.addr);
            work_queue_.insert(sym.addr);
        }
    }
}

void Analyzer::explore_block(uint64_t addr) {
    if (visited_.count(addr)) return;

    BasicBlock bb;
    bb.start = addr;
    bb.end = 0;
    bb.func_addr = 0;
    bb.has_indirect_branch = false;
    bb.is_call = false;
    bb.is_ret = false;
    bb.is_syscall = false;

    uint64_t pc = addr;
    uint8_t buf[15];

    while (true) {
        size_t nread = read_code(pc, buf, sizeof(buf));
        if (nread == 0) break;

        FdInstr instr;
        int len = fd_decode(buf, nread, 64, pc, &instr);
        if (len <= 0) break;

        unsigned type = FD_TYPE(&instr);
        uint64_t next_pc = pc + len;

        // Check for syscall — rellume treats SYSCALL as a basic block
        // boundary (calls the syscall helper, then returns to dispatch).
        // So we end the block here and add the continuation as successor.
        if (type == FDI_SYSCALL) {
            bb.is_syscall = true;
            bb.end = next_pc;
            bb.successors.push_back(next_pc);
            if (!visited_.count(next_pc))
                work_queue_.insert(next_pc);
            break;
        }

        // UD2 — trap, end of block
        if (type == FDI_UD2 || type == FDI_UD1 || type == FDI_UD0) {
            bb.end = next_pc;
            break;
        }

        // HLT — end of block
        if (type == FDI_HLT) {
            bb.end = next_pc;
            break;
        }

        // INT3 — padding/trap, end of block
        if (type == FDI_INT3) {
            bb.end = next_pc;
            break;
        }

        // Unconditional JMP
        if (type == FDI_JMP) {
            bb.end = next_pc;
            uint64_t target;
            if (get_branch_target(&instr, next_pc, &target)) {
                bb.successors.push_back(target);
                if (!visited_.count(target))
                    work_queue_.insert(target);
            } else {
                // Indirect jump — can't resolve statically
                bb.has_indirect_branch = true;
                unresolved_.insert(pc);
            }
            break;
        }

        // Conditional JMP
        if (is_cond_jump(type)) {
            bb.end = next_pc;
            // Fall-through
            bb.successors.push_back(next_pc);
            if (!visited_.count(next_pc))
                work_queue_.insert(next_pc);
            // Branch target
            uint64_t target;
            if (get_branch_target(&instr, next_pc, &target)) {
                bb.successors.push_back(target);
                if (!visited_.count(target))
                    work_queue_.insert(target);
            }
            break;
        }

        // CALL
        if (type == FDI_CALL) {
            bb.is_call = true;
            bb.end = next_pc;
            // Fall-through (return address)
            bb.successors.push_back(next_pc);
            if (!visited_.count(next_pc))
                work_queue_.insert(next_pc);
            // Call target → new function entry
            uint64_t target;
            if (get_branch_target(&instr, next_pc, &target)) {
                function_entries_.insert(target);
                if (!visited_.count(target))
                    work_queue_.insert(target);
            } else {
                // Indirect call
                bb.has_indirect_branch = true;
                unresolved_.insert(pc);
            }
            break;
        }

        // RET
        if (type == FDI_RET || type == FDI_RETF) {
            bb.end = next_pc;
            bb.is_ret = true;
            break;
        }

        // Check if next address is already a known block start (split point)
        if (visited_.count(next_pc) || blocks_.count(next_pc)) {
            bb.end = next_pc;
            bb.successors.push_back(next_pc);
            break;
        }

        pc = next_pc;
    }

    // If we fell off without setting end (e.g., decode failure), set it
    if (bb.end == 0)
        bb.end = pc;

    // Only add non-empty blocks
    if (bb.end > bb.start) {
        visited_.insert(addr);
        blocks_[addr] = bb;
    }
}

void Analyzer::build_functions(AnalysisResult& result) {
    // Sort function entries
    std::vector<uint64_t> func_addrs(function_entries_.begin(), function_entries_.end());
    std::sort(func_addrs.begin(), func_addrs.end());

    // Assign blocks to functions: each block belongs to the nearest
    // function entry at or before its start address
    for (auto& [addr, bb] : blocks_) {
        auto it = std::upper_bound(func_addrs.begin(), func_addrs.end(), addr);
        if (it != func_addrs.begin()) {
            --it;
            bb.func_addr = *it;
        }
    }

    // Build function objects
    for (uint64_t faddr : func_addrs) {
        // Check if we actually have any blocks for this function
        bool has_blocks = false;
        for (const auto& [addr, bb] : blocks_) {
            if (bb.func_addr == faddr) {
                has_blocks = true;
                break;
            }
        }
        if (!has_blocks) continue;

        Function func;
        func.start = faddr;
        func.end = faddr;
        func.has_indirect_jumps = false;
        func.from_symbol = false;

        // Find name from symbol table
        for (const auto& sym : elf_.symbols()) {
            if (sym.addr == faddr && !sym.name.empty()) {
                func.name = sym.name;
                func.from_symbol = true;
                break;
            }
        }

        // Collect blocks
        for (const auto& [addr, bb] : blocks_) {
            if (bb.func_addr != faddr) continue;
            func.blocks.push_back(addr);
            if (bb.end > func.end)
                func.end = bb.end;
            if (bb.has_indirect_branch)
                func.has_indirect_jumps = true;
        }
        std::sort(func.blocks.begin(), func.blocks.end());

        result.functions[faddr] = std::move(func);
    }
}

AnalysisResult Analyzer::analyze() {
    AnalysisResult result;

    // Find .text section bounds
    const ElfSection* text = elf_.find_section(".text");
    if (text) {
        result.text_start = text->addr;
        result.text_size = text->size;
    } else {
        // Fallback: use first executable LOAD segment
        for (const auto& seg : elf_.segments()) {
            if (seg.type == PT_LOAD && (seg.flags & PF_X)) {
                result.text_start = seg.vaddr;
                result.text_size = seg.filesz;
                break;
            }
        }
    }

    // Seed and run recursive descent
    seed_addresses();

    while (!work_queue_.empty()) {
        auto it = work_queue_.begin();
        uint64_t addr = *it;
        work_queue_.erase(it);
        explore_block(addr);
    }

    // Calculate coverage using interval merging to avoid double-counting
    result.bytes_covered = 0;
    std::vector<std::pair<uint64_t, uint64_t>> intervals;
    for (const auto& [addr, bb] : blocks_) {
        uint64_t bb_start = std::max(addr, result.text_start);
        uint64_t bb_end = std::min(bb.end, result.text_start + result.text_size);
        if (bb_end > bb_start)
            intervals.push_back({bb_start, bb_end});
    }
    std::sort(intervals.begin(), intervals.end());
    for (const auto& [s, e] : intervals) {
        if (!result.bytes_covered) {
            result.bytes_covered = e - s;
        } else {
            // Check overlap with accumulated range
            // Simple: just cap at text_size
            result.bytes_covered += e - s;
        }
    }
    // Clamp to text_size
    if (result.bytes_covered > result.text_size)
        result.bytes_covered = result.text_size;

    result.blocks = blocks_;
    result.unresolved_indirects = unresolved_;

    build_functions(result);

    return result;
}

void AnalysisResult::print_summary() const {
    printf("\n=== Static Analysis Summary ===\n");
    printf("  .text range:       0x%lx - 0x%lx (%lu bytes)\n",
           (unsigned long)text_start,
           (unsigned long)(text_start + text_size),
           (unsigned long)text_size);
    printf("  Basic blocks:      %zu\n", blocks.size());
    printf("  Functions:         %zu\n", functions.size());
    printf("  Bytes covered:     %lu / %lu (%.1f%%)\n",
           (unsigned long)bytes_covered,
           (unsigned long)text_size,
           coverage());
    printf("  Unresolved jumps:  %zu\n", unresolved_indirects.size());
    if (!unresolved_indirects.empty()) {
        printf("  Unresolved at:");
        int count = 0;
        for (uint64_t addr : unresolved_indirects) {
            if (count++ >= 10) {
                printf(" ... (%zu more)", unresolved_indirects.size() - 10);
                break;
            }
            printf(" 0x%lx", (unsigned long)addr);
        }
        printf("\n");
    }
}

void AnalysisResult::print_functions() const {
    printf("\n=== Discovered Functions (%zu) ===\n", functions.size());
    for (const auto& [addr, func] : functions) {
        printf("  0x%lx - 0x%lx  blocks=%-3zu  %s%s%s\n",
               (unsigned long)func.start,
               (unsigned long)func.end,
               func.blocks.size(),
               func.name.empty() ? "<unnamed>" : func.name.c_str(),
               func.has_indirect_jumps ? " [indirect]" : "",
               func.from_symbol ? "" : " [discovered]");
    }
}
