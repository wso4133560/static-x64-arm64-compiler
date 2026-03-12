#include "translator.h"

#include <rellume/rellume.h>

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/StandardInstrumentations.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/MemCpyOptimizer.h>

#if __has_include(<llvm/MC/TargetRegistry.h>)
#include <llvm/MC/TargetRegistry.h>
#else
#include <llvm/Support/TargetRegistry.h>
#endif

#include <cstdio>
#include <elf.h>
#include <set>

#define SPTR_ADDR_SPACE 1

// Context passed to Rellume's memory access callback
struct MemAccessContext {
    const ElfInput* elf;
};

// Rellume memory access callback: reads guest code from ELF
static size_t aot_mem_access(size_t addr, uint8_t* buf, size_t bufsz,
                             void* user_arg) {
    auto* ctx = reinterpret_cast<MemAccessContext*>(user_arg);
    return ctx->elf->read_vaddr(static_cast<uint64_t>(addr), buf, bufsz);
}

// Create a function prototype: void(sptr) for Rellume helpers
static llvm::Function* CreateHelperFunc(llvm::LLVMContext& ctx,
                                        const std::string& name) {
    llvm::Type* sptr = llvm::PointerType::get(ctx, SPTR_ADDR_SPACE);
    llvm::Type* void_ty = llvm::Type::getVoidTy(ctx);
    auto* fn_ty = llvm::FunctionType::get(void_ty, {sptr}, false);
    auto linkage = llvm::GlobalValue::ExternalLinkage;
    return llvm::Function::Create(fn_ty, linkage, name);
}

// Optimize a lifted function (same pipeline as server/optimizer.cc)
static void OptimizeFunc(llvm::Function* fn) {
    llvm::PassBuilder pb;
    llvm::FunctionPassManager fpm{};
    llvm::LoopAnalysisManager lam{};
    llvm::FunctionAnalysisManager fam{};
    llvm::CGSCCAnalysisManager cgam{};
    llvm::ModuleAnalysisManager mam{};
    llvm::PassInstrumentationCallbacks pic{};

    fam.registerPass([&] { return llvm::PassInstrumentationAnalysis(&pic); });
    fam.registerPass([&] { return pb.buildDefaultAAPipeline(); });
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);

    fpm.addPass(llvm::DCEPass());
    fpm.addPass(llvm::EarlyCSEPass(false));
    fpm.addPass(llvm::InstCombinePass());
    fpm.addPass(llvm::MemCpyOptPass());
    fpm.run(*fn, fam);
}

struct Translator::Impl {
    const ElfInput& elf;
    const AnalysisResult& analysis;
    bool verbose;

    LLConfig* rlcfg;
    llvm::LLVMContext ctx;
    std::unique_ptr<llvm::Module> mod;
    llvm::SmallVector<llvm::Function*, 4> helper_fns;

    // AArch64 target machine for code generation
    std::unique_ptr<llvm::TargetMachine> target_machine;
    llvm::MCContext* mc_ctx;
    llvm::SmallVector<char, 4096> obj_buffer;

    MemAccessContext mem_ctx;

    Impl(const ElfInput& elf, const AnalysisResult& analysis, bool verbose)
            : elf(elf), analysis(analysis), verbose(verbose), mc_ctx(nullptr) {
        mem_ctx.elf = &elf;

        // Initialize LLVM targets — we need AArch64 for AOT output
        llvm::InitializeAllTargets();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllAsmPrinters();

        // Set up Rellume config for x86-64 guest
        rlcfg = ll_config_new();
        ll_config_set_architecture(rlcfg, "x86-64");
        ll_config_set_sptr_addrspace(rlcfg, SPTR_ADDR_SPACE);
        ll_config_enable_overflow_intrinsics(rlcfg, false);
        ll_config_set_call_ret_clobber_flags(rlcfg, true);

        // Create syscall helper (will be resolved at link time)
        auto syscall_fn = CreateHelperFunc(ctx, "syscall");
        helper_fns.push_back(syscall_fn);
        ll_config_set_syscall_impl(rlcfg, llvm::wrap(syscall_fn));

        // CPUID helper
        llvm::Type* i32 = llvm::Type::getInt32Ty(ctx);
        llvm::Type* i64 = llvm::Type::getInt64Ty(ctx);
        auto i64_i64 = llvm::StructType::get(i64, i64);
        auto cpuinfo_fn_ty = llvm::FunctionType::get(i64_i64, {i32, i32}, false);
        auto cpuinfo_fn = llvm::Function::Create(
            cpuinfo_fn_ty, llvm::GlobalValue::ExternalLinkage, "cpuid");
        helper_fns.push_back(cpuinfo_fn);
        ll_config_set_cpuinfo_func(rlcfg, llvm::wrap(cpuinfo_fn));

        // Create the LLVM module
        mod = std::make_unique<llvm::Module>("instrew-aot", ctx);
        for (auto* fn : helper_fns)
            mod->getFunctionList().push_back(fn);

        // Set up AArch64 target machine
        setup_target();
    }

    ~Impl() {
        ll_config_free(rlcfg);
    }

    void setup_target() {
        std::string triple = "aarch64-unknown-linux-gnu";
        std::string error;
        const llvm::Target* the_target =
            llvm::TargetRegistry::lookupTarget(triple, error);
        if (!the_target) {
            fprintf(stderr, "error: cannot find AArch64 target: %s\n",
                    error.c_str());
            abort();
        }

        llvm::TargetOptions opts;
        // Use PIC + Large code model for AOT (addresses not known at compile)
        target_machine.reset(the_target->createTargetMachine(
            triple, /*CPU=*/"", /*Features=*/"", opts,
            llvm::Reloc::PIC_,
            llvm::CodeModel::Small,
#if LL_LLVM_MAJOR < 18
            static_cast<llvm::CodeGenOpt::Level>(2),
#else
            llvm::CodeGenOpt::getLevel(2).value_or(
                llvm::CodeGenOptLevel::Default),
#endif
            /*JIT=*/false
        ));
        if (!target_machine) {
            fprintf(stderr, "error: cannot create AArch64 target machine\n");
            abort();
        }
    }

    bool generate_object(llvm::Module* m, llvm::SmallVectorImpl<char>& out) {
        m->setDataLayout(target_machine->createDataLayout());
        out.clear();

        llvm::raw_svector_ostream stream(out);
        llvm::legacy::PassManager pm;
        if (target_machine->addPassesToEmitMC(pm, mc_ctx, stream, true)) {
            fprintf(stderr, "error: target doesn't support MC emission\n");
            return false;
        }
        pm.run(*m);
        return true;
    }

    TranslatedFunc translate_one(uint64_t addr, const std::string& name) {
        TranslatedFunc result;
        result.guest_addr = addr;
        result.name = name;
        result.success = false;

        // Create a fresh module for this function
        auto func_mod = std::make_unique<llvm::Module>(
            "func_" + llvm::Twine::utohexstr(addr).str(), ctx);

        // Re-add helper declarations to this module
        for (auto* orig_fn : helper_fns) {
            auto fn_ty = orig_fn->getFunctionType();
            auto* decl = llvm::Function::Create(
                fn_ty, llvm::GlobalValue::ExternalLinkage,
                orig_fn->getName(), func_mod.get());
            (void)decl;
        }

        // Lift with Rellume
        LLFunc* rlfn = ll_func_new(llvm::wrap(func_mod.get()), rlcfg);
        int fail = ll_func_decode_cfg(rlfn, addr, aot_mem_access,
                                      reinterpret_cast<void*>(&mem_ctx));
        if (fail) {
            if (verbose)
                fprintf(stderr, "  [FAIL] decode 0x%lx (%s)\n",
                        (unsigned long)addr, name.c_str());
            ll_func_dispose(rlfn);
            return result;
        }

        LLVMValueRef fn_wrapped = ll_func_lift(rlfn);
        if (!fn_wrapped) {
            if (verbose)
                fprintf(stderr, "  [FAIL] lift 0x%lx (%s)\n",
                        (unsigned long)addr, name.c_str());
            ll_func_dispose(rlfn);
            return result;
        }

        llvm::Function* fn = llvm::unwrap<llvm::Function>(fn_wrapped);
        fn->setName("aot_" + llvm::Twine::utohexstr(addr));
        ll_func_dispose(rlfn);

        // Optimize
        OptimizeFunc(fn);

        // Generate AArch64 object code
        if (!generate_object(func_mod.get(), result.obj_code)) {
            if (verbose)
                fprintf(stderr, "  [FAIL] codegen 0x%lx (%s)\n",
                        (unsigned long)addr, name.c_str());
            return result;
        }

        result.success = true;
        if (verbose)
            printf("  [OK]   0x%lx (%s) -> %zu bytes\n",
                   (unsigned long)addr, name.c_str(),
                   result.obj_code.size());
        return result;
    }
};

Translator::Translator(const ElfInput& elf, const AnalysisResult& analysis,
                       bool verbose)
    : impl_(std::make_unique<Impl>(elf, analysis, verbose)) {}

Translator::~Translator() = default;

TranslationResult Translator::translate_all() {
    TranslationResult result;
    result.succeeded = 0;
    result.failed = 0;

    printf("\n=== Phase 2: Batch AOT Translation ===\n");

    // Collect all addresses that need translation:
    // 1. Function entry points
    // 2. Return continuations (fall-through after CALL basic blocks)
    std::set<uint64_t> translate_addrs;
    std::map<uint64_t, std::string> addr_names;

    for (const auto& [addr, func] : impl_->analysis.functions) {
        translate_addrs.insert(addr);
        addr_names[addr] = func.name;
    }

    // Find CALL and SYSCALL continuation addresses — these are where
    // execution resumes after a called function RETurns or after the
    // syscall helper returns. They need their own translations.
    unsigned cont_count = 0;
    for (const auto& [addr, bb] : impl_->analysis.blocks) {
        if (bb.is_call || bb.is_syscall) {
            for (uint64_t succ : bb.successors) {
                // The fall-through successor is the return continuation.
                // Skip if it's already a function entry.
                if (succ != addr && translate_addrs.insert(succ).second) {
                    char name_buf[64];
                    snprintf(name_buf, sizeof(name_buf), "cont_0x%lx",
                             (unsigned long)succ);
                    addr_names[succ] = name_buf;
                    cont_count++;
                }
            }
        }
    }

    result.total = translate_addrs.size();
    printf("Translating %u entries (%zu functions + %u continuations)...\n",
           result.total,
           impl_->analysis.functions.size(), cont_count);

    for (uint64_t addr : translate_addrs) {
        TranslatedFunc tf = impl_->translate_one(addr, addr_names[addr]);
        if (tf.success)
            result.succeeded++;
        else
            result.failed++;
        result.functions.push_back(std::move(tf));
    }

    return result;
}

void TranslationResult::print_summary() const {
    printf("\n--- Translation Summary ---\n");
    printf("  Total functions:  %u\n", total);
    printf("  Succeeded:        %u\n", succeeded);
    printf("  Failed:           %u\n", failed);
    if (total > 0)
        printf("  Success rate:     %.1f%%\n",
               (double)succeeded / total * 100.0);

    size_t total_bytes = 0;
    for (const auto& f : functions)
        if (f.success)
            total_bytes += f.obj_code.size();
    printf("  Total code size:  %zu bytes\n", total_bytes);
}
