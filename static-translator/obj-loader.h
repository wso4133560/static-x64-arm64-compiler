#ifndef _INSTREW_AOT_OBJ_LOADER_H
#define _INSTREW_AOT_OBJ_LOADER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

// Symbol resolver callback: given a symbol name, return its address.
// Returns 0 if the symbol is not found.
using SymbolResolver = std::function<uint64_t(const std::string& name)>;

// Load a relocatable ELF object (.o) into executable memory.
// Applies relocations using the provided symbol resolver.
// Returns the address of the first function symbol, or nullptr on failure.
// out_base receives the mmap'd base address (for munmap).
// out_size receives the total mapped size.
void* obj_load_func(const void* obj_data, size_t obj_size,
                    const SymbolResolver& resolver,
                    void** out_base, size_t* out_size);

#endif
