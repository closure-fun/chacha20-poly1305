cmake_minimum_required( VERSION 3.20 )

project( chacha20_poly1305 LANGUAGES CXX )

add_library( chacha20_poly1305 chacha20_poly1305.cxx chacha20_poly1305_simd.cxx )
add_library( chacha20_poly1305::chacha20_poly1305 ALIAS chacha20_poly1305 )

target_include_directories( chacha20_poly1305 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" )
target_compile_features( chacha20_poly1305 PUBLIC cxx_std_23 )

enable_testing( )

option( CHACHA20_POLY1305_BUILD_TESTS "Build the rfc 8439 test suite" ON )
option( CHACHA20_POLY1305_BUILD_BENCH "Build the benchmark tool" OFF )
option( CHACHA20_POLY1305_BENCH_EXTERNAL "Benchmark against openssl and libsodium when they are found ( benchmark only, the library itself never links them )" OFF )
option( CHACHA20_POLY1305_MSVC_SIMD_ARCH "Compile the simd unit with /arch:AVX2 on MSVC x64 (codegen quality only; intrinsics emit their instructions either way)" ON )

if( MSVC AND CHACHA20_POLY1305_MSVC_SIMD_ARCH AND CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|i[3-6]86" )
	set_source_files_properties( chacha20_poly1305_simd.cxx PROPERTIES COMPILE_OPTIONS "/arch:AVX2" )
endif()

if( CHACHA20_POLY1305_BUILD_TESTS )
	add_subdirectory( tests )
endif()

if( CHACHA20_POLY1305_BUILD_BENCH )
	add_subdirectory( bench )
endif()
