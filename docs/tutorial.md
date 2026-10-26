# chacha20-poly1305 tutorial

a practical guide to every function in the library. all examples assume:

```c++
#include "chacha20_poly1305.hxx"
```

the library compiles as c++20 everywhere; building as c++23 upgrades the convenience api from `std::optional` to `std::expected` ( same call signatures, richer error reporting ).

-----

## 1. the three key types

```c++
aead::key_t     key;     // 32 bytes, .bytes is a std::array< std::uint8_t, 32 >
aead::nonce_t   nonce;   // 12 bytes
aead::tag_t     tag;     // 16 bytes, the authentication tag
```

fill them from any byte source with `from_span`:

```c++
std::vector< std::uint8_t > raw_key = get_key_from_somewhere( );   // at least 32 bytes
aead::key_t key = aead::key_t::from_span( raw_key );

std::vector< std::uint8_t > raw_nonce = get_nonce( );              // at least 12 bytes
aead::nonce_t nonce = aead::nonce_t::from_span( raw_nonce );
```

`key_t`, `nonce_t` and `tag_t` are trivially copyable value types, safe to store in structs, pass by reference or serialize.

## 2. the nonce rule ( read this once, remember it forever )

a `( key, nonce )` pair must never be reused for two different messages. reusing it breaks confidentiality completely and allows tag forgery.

the recommended pattern is a counter nonce: keep a 12 byte array where the first 4 or 8 bytes are a monotonically increasing counter and the rest is a random session id generated once per key. counters never collide unless the counter wraps ( 2^32 or 2^64 messages, far beyond practical use ).

```c++
std::uint64_t counter = 0;

aead::nonce_t make_nonce( std::uint64_t session_id, std::uint64_t counter )
{
    aead::nonce_t nonce {};

    // little endian counter in the first 8 bytes, session id in the last 4
    for ( int idx = 0; idx < 8; ++idx )
        nonce.bytes[ idx ] = static_cast< std::uint8_t >( counter >> ( idx * 8 ) );
    
    for ( int idx = 0; idx < 4; ++idx )
        nonce.bytes[ 8 + idx ] = static_cast< std::uint8_t >( session_id >> ( idx * 8 ) );
    
    return nonce;
}
```

random nonces also work but collide after ~2^32 messages under one key ( birthday bound ), so counter nonces are safer for long lived keys.

## 3. encrypt and decrypt ( the main api )

spans in, spans out, zero allocations, works with vectors, arrays and raw memory:

```c++
std::vector< std::uint8_t > plain = ...;   // the message
std::vector< std::uint8_t > aad   = ...;   // authenticated but not encrypted data ( can be empty )

std::vector< std::uint8_t > cipher( plain.size( ) );   // same size as plain

aead::tag_t tag = aead::encrypt( cipher, plain, aad, key, nonce );
// cipher now holds the ciphertext, tag authenticates aad || plain
```

send `cipher`, `tag` ( and `aad` if the receiver does not know it ). decryption verifies first, then decrypts:

```c++
std::vector< std::uint8_t > plain_out( cipher.size( ) );

if ( aead::decrypt( plain_out, cipher, aad, key, nonce, tag ) )
{
    // authentic, plain_out holds the recovered plaintext
}
else
{
    // the message was tampered with, plain_out contents are unspecified
}
```

if the tag does not match, `decrypt` returns false and never writes plaintext into your buffer.

## 4. convenience api ( ciphertext || tag in one buffer )

for wire formats where you want one blob, the convenience overloads append the 16 byte tag to the ciphertext:

```c++
// c++23: std::expected< std::vector< std::uint8_t >, aead::error_t >
// c++20: std::optional< std::vector< std::uint8_t > >
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
else
{
    // tampered or truncated input
}
```

under c++23 the error reason is available: `sealed.error( )` is `aead::error_t::auth_failed` or `aead::error_t::invalid_size`.

## 5. buffers: vectors, arrays, raw memory, in place

every span parameter accepts anything contiguous:

```c++
std::array< std::uint8_t, 64 > packet {};
aead::tag_t tag = aead::encrypt( packet, packet, aad, key, nonce );   // in place, fixed array

std::uint8_t raw[ 128 ];
aead::tag_t tag2 = aead::encrypt( { raw, 128 }, { raw, 128 }, aad, key, nonce );   // raw c array
```

in place operation ( encrypting a buffer over itself ) is supported when the destination and source spans are exactly the same span:

```c++
aead::tag_t tag = aead::encrypt( buffer, buffer, aad, key, nonce );       // encrypt in place
bool ok = aead::decrypt( buffer, buffer, aad, key, nonce, tag );          // decrypt in place
```

partially overlapping spans ( offset by a few bytes ) are not supported and are undefined behavior, same restriction as `std::memcpy`.

## 6. additional authenticated data ( aad )

aad is data that is authenticated but not encrypted: packet headers, sequence numbers, message types. the receiver must supply byte identical aad or authentication fails:

```c++
struct packet_header { std::uint32_t sequence; std::uint8_t type; };

packet_header header {};
aead::tag_t tag = aead::encrypt( cipher, plain, { reinterpret_cast< const std::uint8_t* >( &header ), sizeof( header ) }, key, nonce );

// on the receiving side the same header bytes must be passed to decrypt
bool ok = aead::decrypt( plain_out, cipher, { reinterpret_cast< const std::uint8_t* >( &header ), sizeof( header ) }, key, nonce, tag );
```

binding sequence numbers into the aad also gives replay protection: a captured packet replayed out of order decrypts fine but its sequence number check on the plaintext fails, and a replayed packet under a new counter-nonce fails authentication outright.

## 7. raw primitives

the building blocks are exposed for cases where rfc 8439 aead framing is not what you need:

```c++
// chacha20 keystream xor, counter defaults to 0
aead::chacha20::xor_stream( destination, source, key, nonce, counter );
// destination and source may alias exactly ( in place ) or not at all

// one shot poly1305 mac over a message with a one time key
aead::tag_t tag = aead::poly1305::mac( message, one_time_key );

// constant time tag comparison
bool equal = aead::poly1305::verify( tag_a, tag_b );
```

the poly1305 key must be unique per message ( it is a one time key ). in the aead construction the library derives it from chacha20 block 0 automatically; standalone users must generate it themselves, for example from `chacha20::xor_stream` of 32 zero bytes with a dedicated nonce.

## 8. streaming poly1305

for hashing data that arrives in pieces ( sockets, files ) without buffering it all:

```c++
aead::poly1305::state_t state( one_time_key );

state.absorb( chunk_one );      // any size, any number of times
state.absorb( chunk_two );
state.absorb( last_chunk );

aead::tag_t tag = state.finish( );   // once
```

the state securely wipes its key material on destruction. one shot `mac( )` calls use the same machinery internally.

## 9. what the library guarantees

- rfc 8439 test vectors: every vector in the rfc runs against every backend the cpu supports on every test run.
- constant time tag verification: `verify` and the internal aead comparison fold all 16 tag bytes before branching.
- no authenticated plaintext release: decryption verifies the tag over the ciphertext before decrypting anything.
- secure zeroization: key material inside poly1305 states, derived one time keys and tag comparison buffers are wiped with volatile stores the compiler cannot remove.
- backend equivalence: scalar, sse2, avx2, avx-512 and neon paths are tested to produce byte identical output.

## 10. performance notes

the span based api never allocates; the convenience api allocates one output vector. for maximum throughput reuse caller owned buffers and the span api. see the benchmark tables in `readme.md` for measured numbers against openssl and libsodium, and `bench/bench.cxx` for the harness.
