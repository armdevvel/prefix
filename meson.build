project('libprefix', 'cpp',
    version: '0.0.1',
    default_options : ['warning_level=3', 'cpp_std=c++14']
  )

add_global_arguments('-Wno-gnu-zero-variadic-macro-arguments', language: 'cpp') ##__VA_ARGS__

subdir('_user') # specify e.g. debug flags in `meson.build` there

subdir('src') # library files

lib = shared_library('prefix',
    lib_files,
    include_directories: ['include', 'src'],
    install: true
)

subdir('samples')

executable('familiarize',
    test_files,
    include_directories: ['include', 'src'],
    link_with: [lib],
    install: true
  )

install_headers('include/paths.h', subdir: 'prefix')
