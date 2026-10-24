# chacha20-poly1305

A from scratch C++23 implementation of the `ChaCha20` & `Poly1305` ciphers described in [RFC 8439](https://www.rfc-editor.org/info/rfc8439), with runtime dispatched SIMD backends.

- portable scalar fallback that compiles everywhere ( little endian required )
- x86-64: SSE2 ( 4 blocks ), AVX2 ( 8 blocks ), AVX-512F ( 16 blocks ) chacha20 kernels, AVX2 4-block poly1305 kernel
- aarch64: NEON ( 4 blocks ) chacha20 kernel
- zero allocations in the span based aead api, streaming poly1305, constant time tag verification, secure zeroization of key material

the extended-precision-integers dependency is gone, poly1305 now uses 5x26-bit limbs like poly1305-donna.

-----

# Benchmarks

everything below is throughput in MiB/s ( megabytes of input processed per second ), higher is better. all three libraries were compiled with the same compiler ( clang 22, `-O2` ) and run on the same machine, each picking its fastest available backend ( AVX2 here, this cpu has no AVX-512 ):

- **this library** - the one in this repo
- **tinychacha** - [gibme-c/tinychacha](https://github.com/gibme-c/tinychacha), run with its own `bench_all` tool
- **original fork** - this repo before the rewrite, scalar chacha20 and a 320-bit bigint poly1305

## aead encrypt ( encrypt + authenticate one message )

| message size | this library | tinychacha | original fork |
| --- | --- | --- | --- |
| 64B | 212 | 105 | 3.9 |
| 256B | 559 | 235 | 5.0 |
| 1KiB | 1,385 | 338 | 5.5 |
| 4KiB | 1,824 | 383 | 5.4 |
| 64KiB | 2,064 | 277 | 5.5 |
| 1MiB | 2,053 | 302 | 5.5 |

about **2x faster than tinychacha** on small packets and **7x** on large ones, and roughly **370x faster than the original fork** ( its bigint poly1305 capped everything at ~5.5 MiB/s ).

## raw cipher speed ( 1 MiB messages )

| primitive | this library | tinychacha | original fork |
| --- | --- | --- | --- |
| chacha20 | 3,763 | 590 | 653 |
| poly1305 | 4,509 | 1,721 | 5.6 |

run your own numbers with `-DCHACHA20_POLY1305_BUILD_BENCH=ON`.

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

all test vectors from RFC 8439 ( block function, encryption, poly1305 mac, key generation, aead 2.8.2 and A.5, the full A.3 set ) run against every backend the cpu supports, plus backend equivalence over odd sizes, streaming equivalence, in place roundtrips and tamper rejection.
