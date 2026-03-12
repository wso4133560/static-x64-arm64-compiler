#include "analyzer.h"
#include "elf-input.h"
#include "elf-output.h"
#include "obj-loader.h"
#include "runtime.h"
#include "translator.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <getopt.h>
#include <sys/mman.h>
#include <vector>

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options] <input-elf>\n"
        "\n"
        "Options:\n"
        "  -o <file>    Output AArch64 ELF path (default: a.out.aarch64)\n"
        "  -r           Run translated code in-process (self-test mode)\n"
        "  -v           Verbose output\n"
        "  -h           Show this help\n"
        "\n"
        "Instrew AOT: Static x86-64 to AArch64 binary translator\n",
        prog);
}

// Load translated object code into executable memory and build address map
// Symbol resolver for the obj-loader: resolves runtime helper symbols
static uint64_t resolve_runtime_symbol(const std::string& name) {
    if (name == "syscall")
        return reinterpret_cast<uint64_t>(&aot_syscall);
    if (name == "cpuid")
        return reinterpret_cast<uint64_t>(&aot_cpuid);
    fprintf(stderr, "resolve: unknown symbol '%s'\n", name.c_str());
    return 0;
}

static bool load_translations(const TranslationResult& translation,
                              AddressMap& map,
                              std::vector<void*>& alloc_bases,
                              std::vector<size_t>& alloc_sizes,
                              bool verbose) {
    SymbolResolver resolver = resolve_runtime_symbol;

    for (const auto& tf : translation.functions) {
        if (!tf.success)
            continue;

        void* base = nullptr;
        size_t size = 0;
        void* func = obj_load_func(tf.obj_code.data(), tf.obj_code.size(),
                                   resolver, &base, &size);
        if (!func) {
            fprintf(stderr, "  [FAIL] load obj for 0x%lx (%s)\n",
                    (unsigned long)tf.guest_addr, tf.name.c_str());
            continue;
        }

        alloc_bases.push_back(base);
        alloc_sizes.push_back(size);

        auto fn_ptr = reinterpret_cast<TranslatedFuncPtr>(func);
        map.add(tf.guest_addr, fn_ptr);

        if (verbose)
            printf("  [LOAD] 0x%lx -> %p (%s)\n",
                   (unsigned long)tf.guest_addr, func, tf.name.c_str());
    }
    return map.size() > 0;
}

int main(int argc, char** argv) {
    const char* output_path = "a.out.aarch64";
    bool verbose = false;
    bool run_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "o:rvh")) != -1) {
        switch (opt) {
        case 'o':
            output_path = optarg;
            break;
        case 'r':
            run_mode = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "error: no input file specified\n");
        print_usage(argv[0]);
        return 1;
    }

    const char* input_path = argv[optind];

    // Phase 0: Parse input ELF
    ElfInput elf;
    if (!elf.load(input_path)) {
        fprintf(stderr, "error: failed to load '%s'\n", input_path);
        return 1;
    }

    // Validate: must be x86-64
    if (elf.machine() != EM_X86_64) {
        fprintf(stderr, "error: input is not x86-64 (machine=0x%x)\n", elf.machine());
        return 1;
    }

    // Validate: must be EXEC or DYN
    if (elf.type() != ET_EXEC && elf.type() != ET_DYN) {
        fprintf(stderr, "error: input is not an executable (type=0x%x)\n", elf.type());
        return 1;
    }

    if (verbose) {
        elf.print_info();
    }

    printf("\ninstrew-aot: input '%s' loaded successfully\n", input_path);
    printf("  machine:    x86-64\n");
    printf("  type:       %s\n", elf.type() == ET_EXEC ? "EXEC" : "DYN (PIE)");
    printf("  entry:      0x%lx\n", (unsigned long)elf.entry());
    printf("  sections:   %zu\n", elf.sections().size());
    printf("  segments:   %zu\n", elf.segments().size());
    printf("  symbols:    %zu\n", elf.symbols().size());
    printf("  functions:  %zu\n", elf.function_symbols().size());
    printf("  output:     %s\n", output_path);

    // Phase 1: Static analysis (CFG recovery)
    Analyzer analyzer(elf);
    AnalysisResult analysis = analyzer.analyze();
    analysis.print_summary();
    if (verbose) {
        analysis.print_functions();
    }

    // Phase 2: Batch AOT translation
    Translator translator(elf, analysis, verbose);
    TranslationResult translation = translator.translate_all();
    translation.print_summary();

    // Phase 3: Runtime support
    if (run_mode) {
        printf("\n=== Phase 3: Runtime Execution ===\n");

        // Load translated objects into executable memory
        AddressMap addr_map;
        std::vector<void*> alloc_bases;
        std::vector<size_t> alloc_sizes;

        printf("Loading translated functions...\n");
        if (!load_translations(translation, addr_map, alloc_bases,
                               alloc_sizes, verbose)) {
            fprintf(stderr, "error: no functions loaded\n");
            return 1;
        }
        printf("Loaded %zu functions into address map\n", addr_map.size());

        // Allocate guest stack (8 MB)
        constexpr size_t STACK_SIZE = 8 * 1024 * 1024;
        void* stack = mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED) {
            perror("mmap stack");
            return 1;
        }
        uint64_t stack_top = reinterpret_cast<uint64_t>(stack) + STACK_SIZE;
        // Align to 16 bytes (x86-64 ABI)
        stack_top &= ~0xFULL;

        // Set up minimal stack: argc=0, argv=NULL, envp=NULL, auxv terminator
        // Stack layout (growing down):
        //   [stack_top - 8]  = 0 (auxv terminator AT_NULL)
        //   [stack_top - 16] = 0 (auxv terminator value)
        //   [stack_top - 24] = 0 (envp NULL terminator)
        //   [stack_top - 32] = 0 (argv NULL terminator)
        //   [stack_top - 40] = 0 (argc = 0)
        auto* sp = reinterpret_cast<uint64_t*>(stack_top);
        *(--sp) = 0;  // AT_NULL value
        *(--sp) = 0;  // AT_NULL key
        *(--sp) = 0;  // envp terminator
        *(--sp) = 0;  // argv terminator
        *(--sp) = 0;  // argc
        stack_top = reinterpret_cast<uint64_t>(sp);

        // Initialize CPU state
        AotCpuState cpu;
        aot_init_cpu(&cpu, elf.entry(), stack_top);

        printf("Entering dispatch loop (entry=0x%lx, rsp=0x%lx)...\n",
               (unsigned long)elf.entry(), (unsigned long)stack_top);

        // Run!
        aot_dispatch_loop(&cpu, addr_map);

        // Should not reach here (exit syscall terminates)
        fprintf(stderr, "error: dispatch loop returned unexpectedly\n");

        // Cleanup
        for (size_t i = 0; i < alloc_bases.size(); i++)
            munmap(alloc_bases[i], alloc_sizes[i]);
        munmap(stack, STACK_SIZE);
        return 1;
    }

    // Phase 4: ELF output generation
    if (!emit_aarch64_elf(translation, elf, output_path, verbose)) {
        fprintf(stderr, "error: ELF output generation failed\n");
        return 1;
    }

    return 0;
}
