#ifndef _INSTREW_STATIC_TRANSLATOR_H
#define _INSTREW_STATIC_TRANSLATOR_H

#include "analyzer.h"
#include "elf-input.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <llvm/ADT/SmallVector.h>

struct TranslatedFunc {
    uint64_t guest_addr;
    std::string name;
    llvm::SmallVector<char, 4096> obj_code;  // AArch64 machine code object
    bool success;
};

struct TranslationResult {
    std::vector<TranslatedFunc> functions;
    unsigned total;
    unsigned succeeded;
    unsigned failed;

    void print_summary() const;
};

class Translator {
public:
    Translator(const ElfInput& elf, const AnalysisResult& analysis,
               bool verbose = false);
    ~Translator();

    TranslationResult translate_all();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif
