# chacha20-poly1305

A from scratch C++23 implementation of the `ChaCha20` & `Poly1305` ciphers described in [RFC 8439](https://www.rfc-editor.org/info/rfc8439), with runtime dispatched SIMD backends.

- portable scalar fallback that compiles everywhere ( little endian required )
- x86-64: SSE2 ( 4 blocks ), AVX2 ( 8 blocks ), AVX-512F ( 16 blocks ) chacha20 kernels, AVX2 4-block poly1305 kernel
- aarch64: NEON ( 4 blocks ) chacha20 kernel
- zero allocations in the span based aead api, streaming poly1305, constant time tag verification, secure zeroization of key material

the extended-precision-integers dependency is gone, poly1305 now uses 5x26-bit limbs like poly1305-donna.

-----

# Benchmarks

measured on the same machine and compiler ( clang 22, `-O2` ) against [tinychacha](https://github.com/gibme-c/tinychacha) with its own `bench_all` tool, both libraries dispatching to their AVX2 backends ( AVX-512 unavailable on this cpu ):

| size | chacha20 | poly1305 | aead encrypt |
| --- | --- | --- | --- |
| 64B | 669 vs 502 MiB/s | 1287 vs 990 MiB/s | 211 vs 105 MiB/s |
| 256B | 1539 vs 536 MiB/s | 1973 vs 1452 MiB/s | 552 vs 235 MiB/s |
| 1KiB | 3668 vs 551 MiB/s | 3431 vs 1603 MiB/s | 1366 vs 338 MiB/s |
| 4KiB | 3755 vs 552 MiB/s | 4158 vs 1708 MiB/s | 1819 vs 383 MiB/s |
| 64KiB | 3791 vs 552 MiB/s | 4458 vs 1709 MiB/s | 2037 vs 277 MiB/s |
| 1MiB | 3724 vs 590 MiB/s | 4467 vs 1721 MiB/s | 2034 vs 302 MiB/s |

run your own with `-DCHACHA20_POLY1305_BUILD_BENCH=ON`.

-----

# Usage

```c++
#include "chacha20_poly1305.hxx"

aead::key_t key = aead::key_t::from_span( key_bytes );     // 32 bytes
aead::nonce_t nonce = aead::nonce_t::from_span( nonce );  // 12 bytes, never repeat under the same key

// spans, zero allocations, destination and source may alias exactly for in place use:
const auto tag = aead::encrypt( cipher, plain, aad, key, nonce );
if ( !aead::decrypt( plain_out, cipher, aad, key, nonce, tag ) )
 // authentication failed, plain_out contents are unspecified

// convenience overloads return std::expected, output is ciphertext || tag:
const auto sealed = aead::encrypt( plain, aad, key, nonce );  // -> std::expected<std::vector<std::uint8_t>, aead::error_t>
const auto opened = aead::decrypt( sealed, aad, key, nonce );  // -> std::expected<std::vector<std::uint8_t>, aead::error_t>
```

raw primitives:

```c++
// chacha20 keystream xor, counter defaults to 0
aead::chacha20::xor_stream( destination, source, key, nonce, counter );

// one shot poly1305 mac ( one time key! ) and constant time verify
const auto tag = aead::poly1305::mac( message, one_time_key );
const bool ok = aead::poly1305::verify( tag_a, tag_b );

// streaming poly1305 for chunked input
aead::poly1305::state_t state( one_time_key );
state.absorb( chunk_one );
state.absorb( chunk_two );
const auto tag = state.finish( );
```

decrypt verifies the tag over the ciphertext *before* decrypting, so unauthenticated plaintext never touches your output buffer.

-----

# Building

requires C++23 and a little endian system.

```shell
cmake -S . -B build -DCHACHA20_POLY1305_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

link against the `chacha20_poly1305::chacha20_poly1305` CMake target, or compile `chacha20_poly1305.cxx` + `chacha20_poly1305_simd.cxx` directly into your project.

options:

| option | default | description |
| --- | --- | --- |
| `CHACHA20_POLY1305_BUILD_TESTS` | `ON` | build the rfc 8439 test suite |
| `CHACHA20_POLY1305_BUILD_BENCH` | `OFF` | build the benchmark tool |
| `CHACHA20_POLY1305_MSVC_SIMD_ARCH` | `ON` | compile the simd unit with `/arch:AVX2` on MSVC x64 |
| `CCP_DISABLE_SIMD` | undefined | define to force the portable backend |
| `CCP_DISABLE_AVX512` | undefined | define to drop the AVX-512 backend |

all test vectors from RFC 8439 ( block function, encryption, poly1305 mac, key generation, aead 2.8.2 and A.5, the full A.3 set ) run against every backend the cpu supports, plus backend equivalengthce over odd sizes, streaming equivalengthce, in place roundtrips and tamper rejection.
