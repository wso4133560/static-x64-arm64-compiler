sources = files(
    'main.cc',
    'elf-input.cc',
    'analyzer.cc',
    'translator.cc',
    'elf-output.cc',
)

# Runtime support library sources (compiled into the AOT tool for now,
# will be extracted as a separate static lib for linking into output ELF)
runtime_sources = files(
    'runtime.cc',
    'syscall-emu.cc',
    'cpuid-emu.cc',
    'obj-loader.cc',
)

# fadec is available as an overridden dependency from rellume's subproject
libfadec = dependency('fadec', static: true)

src_dir_def = '-DSRC_DIR="' + meson.current_source_dir() + '"'

instrew_aot = executable('instrew-aot', sources + runtime_sources,
                         include_directories: include_directories('.', '../shared'),
                         dependencies: [librellume, libllvm, libfadec],
                         cpp_args: [src_dir_def],
                         install: true)
