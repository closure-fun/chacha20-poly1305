# chacha20-poly1305

A from scratch C++23 implementation of the `ChaCha20` & `Poly1305` ciphers described in [RFC 8439](https://www.rfc-editor.org/info/rfc8439), with runtime dispatched SIMD backends.

- portable scalar fallback that compiles everywhere ( little endian required )
- x86-64: SSE2 ( 4 blocks ), AVX2 ( 8 blocks ), AVX-512F ( 16 blocks ) chacha20 kernels, AVX2 4-block poly1305 kernel
- aarch64: NEON ( 4 blocks ) chacha20 kernel
- zero allocations in the span based aead api, streaming poly1305, constant time tag verification, secure zeroization of key material

the extended-precision-integers dependency is gone, poly1305 now uses 5x26-bit limbs like poly1305-donna.

-----

# Usage

```c++
#include "chacha20_poly1305.hxx"

aead::key_t key = aead::key_t::from_span( key_bytes );     // 32 bytes
aead::nonce_t nonce = aead::nonce_t::from_span( nonce );   // 12 bytes, never repeat under the same key
```

## encrypt and decrypt

spans in, spans out, zero allocations, works with vectors, arrays and raw memory. destination and source may alias exactly for in place use:

```c++
std::vector< std::uint8_t > cipher( plain.size( ) );

aead::tag_t tag = aead::encrypt( cipher, plain, aad, key, nonce );
// cipher now holds the ciphertext, tag authenticates aad || plain

std::vector< std::uint8_t > plain_out( cipher.size( ) );

if ( aead::decrypt( plain_out, cipher, aad, key, nonce, tag ) )
{
    // authentic, plain_out holds the recovered plaintext
}
else
{
    // tampered, plain_out contents are unspecified
}
```

decrypt verifies the tag over the ciphertext *before* decrypting, so unauthenticated plaintext never touches your output buffer.

## convenience api ( ciphertext || tag in one buffer )

under c++23 the overloads return std::expected, under c++20 std::optional:

```c++
auto sealed = aead::encrypt( plain, aad, key, nonce );

if ( sealed )
{
    // *sealed is ciphertext followed by the 16 byte tag, ready to send
}

auto opened = aead::decrypt( *sealed, aad, key, nonce );

if ( opened )
{
    // *opened is the recovered plaintext
}
```

## in place and buffers

every span parameter accepts vectors, arrays and raw memory:

```c++
std::array< std::uint8_t, 64 > packet {};
aead::tag_t tag = aead::encrypt( packet, packet, aad, key, nonce );   // in place, fixed array
```

partially overlapping spans are not supported, same restriction as memcpy.

## the nonce rule

a ( key, nonce ) pair must never be reused for two different messages. the recommended pattern is a counter nonce: keep a 12 byte array where the first bytes are a monotonically increasing counter and the rest is a random session id generated once per key.

## additional authenticated data ( aad )

aad is authenticated but not encrypted: packet headers, sequence numbers, message types. the receiver must supply byte identical aad or authentication fails. binding sequence numbers into the aad also gives replay protection.

## raw primitives

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

the poly1305 key must be unique per message ( it is a one time key ). in the aead construction the library derives it from chacha20 block 0 automatically.

# Benchmarks

compared against **OpenSSL** and **libsodium**, using each library's supported public api for the same cryptographic construction: ietf chacha20-poly1305 with a 96 bit nonce and 12 byte aad for the aead rows, raw chacha20 keystream and raw poly1305 for the primitive rows. before timing, ciphertext, tag, raw stream and mac equivalence against this library was verified, and every library rejected a tampered authentication tag.

openssl and libsodium are optional, benchmark-only dependencies. the library itself never links them; without them their columns report unavailable.

## how to run

```shell
cmake -S . -B build -DCHACHA20_POLY1305_BUILD_BENCH=ON -DCHACHA20_POLY1305_BENCH_EXTERNAL=ON -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
./build/bench/Release/chacha20_poly1305_bench --markdown
```

`--markdown` prints the tables below in readme format; without it a plain text report is printed. omit `-DCHACHA20_POLY1305_BENCH_EXTERNAL` to benchmark only this library.

## reading the numbers

- `1 KiB = 1,024 bytes`, `1 MiB = 1,048,576 bytes`
- `MiB/s` = throughput, how many MiB of input are processed per second. higher is better.
- `ns/op`, `us/op`, `ms/op` = directly measured time for one operation ( the median across repetitions ), including per-operation key setup and authentication, excluding buffer allocation. lower is better.
- `[291..302]` = the minimum and maximum per-operation time across the repetitions.

throughput describes how much input is processed per unit time; per-operation latency describes the duration of one call. example: encrypting a 64 KiB message at the measured 1,989.1 MiB/s:

```text
estimated processing time = input bytes / measured bytes per second
                           = 65,536 / ( 1,989.1 x 1,048,576 )
                           = 0.0000314 s  ~=  31.4 us   ( estimate, derived from throughput )
```

the directly measured per-operation latency for that row is 31.42 us, which matches. for very small messages the measured latency is the authoritative number because it includes fixed per-call costs that a throughput figure can hide.

the tables below are generated by `chacha20_poly1305_bench --markdown`:

## benchmark environment

- cpu: AMD Ryzen 5 5600GT with Radeon Graphics
- compiler: Clang 22.1 ( -O2 )
- os: Windows x64
- backends: this library avx2, openssl OpenSSL 3.6.3 9 Jun 2026, libsodium 1.0.22
- method: median of 7 repetitions, monotonic steady clock, identical inputs and aad,
  preallocated reused buffers, per-operation key setup and authentication included, allocation excluded
- before timing, ciphertext, tag, raw stream and mac equivalence against this library was
  verified, and every library rejected a tampered authentication tag

### aead encrypt

| workload | this library | openssl | libsodium | relative result |
| --- | --- | --- | --- | --- |
| aead encrypt, 64 B | 209.4 MiB/s, 291 ns/op | 82.6 MiB/s, 739 ns/op | 124.0 MiB/s, 492 ns/op | 1.69x faster than libsodium |
| aead encrypt, 256 B | 487.9 MiB/s, 500 ns/op | 289.9 MiB/s, 842 ns/op | 348.2 MiB/s, 701 ns/op | 1.40x faster than libsodium |
| aead encrypt, 1 KiB | 1312.2 MiB/s, 744 ns/op | 938.5 MiB/s, 1.04 us/op | 801.9 MiB/s, 1.22 us/op | 1.40x faster than openssl |
| aead encrypt, 4 KiB | 1891.7 MiB/s, 2.06 us/op | 1943.5 MiB/s, 2.01 us/op | 1054.6 MiB/s, 3.70 us/op | comparable to openssl |
| aead encrypt, 64 KiB | 2128.2 MiB/s, 29.37 us/op | 2841.8 MiB/s, 21.99 us/op | 1147.1 MiB/s, 54.48 us/op | 1.34x slower than openssl |
| aead encrypt, 1 MiB | 2158.6 MiB/s, 463.26 us/op | 2953.5 MiB/s, 338.58 us/op | 1155.5 MiB/s, 865.43 us/op | 1.37x slower than openssl |

### aead decrypt

| workload | this library | openssl | libsodium | relative result |
| --- | --- | --- | --- | --- |
| aead decrypt, 64 B | 199.2 MiB/s, 306 ns/op | 80.2 MiB/s, 761 ns/op | 117.2 MiB/s, 521 ns/op | 1.70x faster than libsodium |
| aead decrypt, 256 B | 486.9 MiB/s, 501 ns/op | 278.0 MiB/s, 878 ns/op | 357.7 MiB/s, 683 ns/op | 1.36x faster than libsodium |
| aead decrypt, 1 KiB | 1293.5 MiB/s, 755 ns/op | 928.8 MiB/s, 1.05 us/op | 801.2 MiB/s, 1.22 us/op | 1.39x faster than openssl |
| aead decrypt, 4 KiB | 1849.7 MiB/s, 2.11 us/op | 1921.5 MiB/s, 2.03 us/op | 1026.7 MiB/s, 3.80 us/op | comparable to openssl |
| aead decrypt, 64 KiB | 2149.1 MiB/s, 29.08 us/op | 2869.1 MiB/s, 21.78 us/op | 1142.7 MiB/s, 54.69 us/op | 1.34x slower than openssl |
| aead decrypt, 1 MiB | 2145.6 MiB/s, 466.06 us/op | 2914.5 MiB/s, 343.11 us/op | 1134.7 MiB/s, 881.27 us/op | 1.36x slower than openssl |

### chacha20

| workload | this library | openssl | libsodium | relative result |
| --- | --- | --- | --- | --- |
| chacha20, 64 B | 646.0 MiB/s, 94 ns/op | 126.7 MiB/s, 482 ns/op | 430.6 MiB/s, 142 ns/op | 1.50x faster than libsodium |
| chacha20, 256 B | 1542.7 MiB/s, 158 ns/op | 460.5 MiB/s, 530 ns/op | 1242.9 MiB/s, 196 ns/op | 1.24x faster than libsodium |
| chacha20, 1 KiB | 3656.0 MiB/s, 267 ns/op | 1518.6 MiB/s, 643 ns/op | 3331.1 MiB/s, 293 ns/op | 1.10x faster than libsodium |
| chacha20, 4 KiB | 3637.9 MiB/s, 1.07 us/op | 2986.4 MiB/s, 1.31 us/op | 3580.1 MiB/s, 1.09 us/op | comparable to libsodium |
| chacha20, 64 KiB | 3729.3 MiB/s, 16.76 us/op | 4287.2 MiB/s, 14.58 us/op | 3634.9 MiB/s, 17.19 us/op | 1.15x slower than openssl |
| chacha20, 1 MiB | 3744.2 MiB/s, 267.08 us/op | 4429.6 MiB/s, 225.75 us/op | 3594.2 MiB/s, 278.22 us/op | 1.18x slower than openssl |

### poly1305

| workload | this library | openssl | libsodium | relative result |
| --- | --- | --- | --- | --- |
| poly1305, 64 B | 1259.1 MiB/s, 48 ns/op | 963.2 MiB/s, 63 ns/op | 872.6 MiB/s, 70 ns/op | 1.31x faster than openssl |
| poly1305, 256 B | 1484.2 MiB/s, 164 ns/op | 2443.1 MiB/s, 100 ns/op | 1343.4 MiB/s, 182 ns/op | 1.65x slower than openssl |
| poly1305, 1 KiB | 3255.3 MiB/s, 300 ns/op | 5317.5 MiB/s, 184 ns/op | 1585.1 MiB/s, 616 ns/op | 1.63x slower than openssl |
| poly1305, 4 KiB | 4646.8 MiB/s, 841 ns/op | 7680.7 MiB/s, 509 ns/op | 1668.8 MiB/s, 2.34 us/op | 1.65x slower than openssl |
| poly1305, 64 KiB | 4936.4 MiB/s, 12.66 us/op | 8591.1 MiB/s, 7.28 us/op | 1656.9 MiB/s, 37.72 us/op | 1.74x slower than openssl |
| poly1305, 1 MiB | 5352.2 MiB/s, 186.84 us/op | 8865.0 MiB/s, 112.80 us/op | 1659.5 MiB/s, 602.60 us/op | 1.66x slower than openssl |

## historical comparison

earlier one-off measurements against [tinychacha](https://github.com/gibme-c/tinychacha) ( run with its own `bench_all` tool ) and this repo before the rewrite ( scalar chacha20, 320-bit bigint poly1305 ). same machine, clang `-O2`, but an older single-pass methodology, so treat these as context rather than a controlled comparison:

| workload | this library | tinychacha | original fork |
| --- | --- | --- | --- |
| aead encrypt 64B | 212 MiB/s | 105 MiB/s | 3.9 MiB/s |
| aead encrypt 1 KiB | 1,385 MiB/s | 338 MiB/s | 5.5 MiB/s |
| aead encrypt 1 MiB | 2,053 MiB/s | 302 MiB/s | 5.5 MiB/s |
| chacha20 1 MiB | 3,763 MiB/s | 590 MiB/s | 653 MiB/s |
| poly1305 1 MiB | 4,509 MiB/s | 1,721 MiB/s | 5.6 MiB/s |

-----

-----

# Building

requires C++20 and a little endian system ( c++23 upgrades the convenience api from std::optional to std::expected automatically ).

```shell
cmake -S . -B build -DCHACHA20_POLY1305_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

link against the `chacha20_poly1305::chacha20_poly1305` CMake target, or compile `chacha20_poly1305.cxx` + `simd.cxx` directly into your project.

options:

| option | default | description |
| --- | --- | --- |
| `CHACHA20_POLY1305_BUILD_TESTS` | `ON` | build the rfc 8439 test suite |
| `CHACHA20_POLY1305_BUILD_BENCH` | `OFF` | build the benchmark tool |
| `CHACHA20_POLY1305_BENCH_EXTERNAL` | `OFF` | benchmark against openssl and libsodium when found, benchmark only, the library never links them |
| `CHACHA20_POLY1305_MSVC_SIMD_ARCH` | `ON` | compile the simd unit with `/arch:AVX2` on MSVC x64 |
| `CCP_DISABLE_SIMD` | undefined | define to force the portable backend |
| `CCP_DISABLE_AVX512` | undefined | define to drop the AVX-512 backend |

all test vectors from RFC 8439 ( block function, encryption, poly1305 mac, key generation, aead 2.8.2 and A.5, the full A.3 set ) run against every backend the cpu supports, plus backend equivalence over odd sizes, streaming equivalence, in place roundtrips and tamper rejection.
