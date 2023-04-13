project('sha256', 'cpp',
  meson_version: '>=1.1.0',
  default_options: [
    'cpp_std=c++17'
  ]
)

Catch2 = dependency('catch2-with-main')
Boost_Endian = dependency('boost', version: '>=1.58')

sha256_lib = static_library('sha256',
  'sha256.cpp',
  'sha256.hpp',
  dependencies: Boost_Endian
)
sha256sum_exe = executable('sha256sum',
  'sha256sum.cpp',
  link_with: sha256_lib
)

if Catch2.found()
  catch2_test = executable('catch2_test',
    'test/test.cpp',
    link_with: sha256_lib,
    dependencies: [Catch2]
  )
  test('unit tests',
    catch2_test,
    protocol: 'tap',
    args: ['-r', 'tap'],
    verbose: true
  )
endif

