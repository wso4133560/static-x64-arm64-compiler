#ifndef _INSTREW_AOT_ELF_OUTPUT_H
#define _INSTREW_AOT_ELF_OUTPUT_H

#include "elf-input.h"
#include "translator.h"

// Emit a standalone AArch64 ELF binary from translated code.
// Creates a temp directory, writes .o files, generates glue assembly and
// a main wrapper, compiles and links everything into a standalone executable.
// Returns true on success.
bool emit_aarch64_elf(const TranslationResult& result, const ElfInput& elf,
                      const char* output_path, bool verbose);

#endif
