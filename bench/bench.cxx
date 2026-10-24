#include "chacha20_poly1305.hxx"

#include <chrono>
#include <cstdio>
#include <vector>

const std::uint8_t bench_key_bytes[ 32 ]   = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
const std::uint8_t bench_nonce_bytes[ 12 ] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

const auto bench_key   = aead::key_t::from_span( std::span< const std::uint8_t >( bench_key_bytes, 32 ) );
const auto bench_nonce = aead::nonce_t::from_span( std::span< const std::uint8_t >( bench_nonce_bytes, 12 ) );

auto measure( const char* label, void ( *fn )( const std::uint8_t*, std::size_t, std::size_t ), std::size_t block_size, std::size_t iterations ) -> double
{
	const std::vector< std::uint8_t > data( block_size, 0xAB );

	const auto start = std::chrono::high_resolution_clock::now( );
	fn( data.data( ), data.size( ), iterations );
	const auto end = std::chrono::high_resolution_clock::now( );

	const double secs		 = std::chrono::duration< double >( end - start ).count( );
	const double mib_per_sec = ( static_cast< double >( block_size ) * iterations / ( 1024.0 * 1024.0 ) ) / secs;

	std::printf( "%-30s %8zu bytes x %6zu iters = %8.2f MiB/s  (%.4f s)\n", label, block_size, iterations, mib_per_sec, secs );
	return mib_per_sec;
}

auto bench_chacha20( const std::uint8_t* data, std::size_t length, std::size_t iters ) -> void
{
	std::vector< std::uint8_t > out( length );
	for ( std::size_t idx = 0; idx < iters; ++idx )
		aead::chacha20::xor_stream( out, std::span< const std::uint8_t >( data, length ), bench_key, bench_nonce, 0 );
}

auto bench_poly1305( const std::uint8_t* data, std::size_t length, std::size_t iters ) -> void
{
	for ( std::size_t idx = 0; idx < iters; ++idx )
		( void )aead::poly1305::mac( std::span< const std::uint8_t >( data, length ), bench_key );
}

auto bench_aead_encrypt( const std::uint8_t* data, std::size_t length, std::size_t iters ) -> void
{
	const std::uint8_t aad[] = { 0x50, 0x51, 0x52, 0x53 };
	std::vector< std::uint8_t > ct( length );
	for ( std::size_t idx = 0; idx < iters; ++idx )
		( void )aead::encrypt( ct, std::span< const std::uint8_t >( data, length ), aad, bench_key, bench_nonce );
}

auto bench_aead_decrypt( const std::uint8_t* data, std::size_t length, std::size_t iters ) -> void
{
	const std::uint8_t aad[] = { 0x50, 0x51, 0x52, 0x53 };
	std::vector< std::uint8_t > ct( length );
	const auto tag = aead::encrypt( ct, std::span< const std::uint8_t >( data, length ), aad, bench_key, bench_nonce );

	std::vector< std::uint8_t > pt( length );
	for ( std::size_t idx = 0; idx < iters; ++idx )
		( void )aead::decrypt( pt, ct, aad, bench_key, bench_nonce, tag );
}

auto main( ) -> int
{
	std::printf( "chacha20-poly1305 benchmarks\n\n" );

	std::printf( "chacha20\n" );
	measure( "chacha20  64B", bench_chacha20, 64, 100000 );
	measure( "chacha20  256B", bench_chacha20, 256, 100000 );
	measure( "chacha20  1KiB", bench_chacha20, 1024, 50000 );
	measure( "chacha20  4KiB", bench_chacha20, 4096, 20000 );
	measure( "chacha20  64KiB", bench_chacha20, 65536, 2000 );
	measure( "chacha20  1MiB", bench_chacha20, 1048576, 100 );

	std::printf( "\npoly1305\n" );
	measure( "poly1305  64B", bench_poly1305, 64, 100000 );
	measure( "poly1305  256B", bench_poly1305, 256, 100000 );
	measure( "poly1305  1KiB", bench_poly1305, 1024, 50000 );
	measure( "poly1305  4KiB", bench_poly1305, 4096, 20000 );
	measure( "poly1305  64KiB", bench_poly1305, 65536, 2000 );
	measure( "poly1305  1MiB", bench_poly1305, 1048576, 100 );

	std::printf( "\naead encrypt\n" );
	measure( "aead encrypt  64B", bench_aead_encrypt, 64, 100000 );
	measure( "aead encrypt  256B", bench_aead_encrypt, 256, 100000 );
	measure( "aead encrypt  1KiB", bench_aead_encrypt, 1024, 50000 );
	measure( "aead encrypt  4KiB", bench_aead_encrypt, 4096, 20000 );
	measure( "aead encrypt  64KiB", bench_aead_encrypt, 65536, 2000 );
	measure( "aead encrypt  1MiB", bench_aead_encrypt, 1048576, 100 );

	std::printf( "\naead decrypt\n" );
	measure( "aead decrypt  64B", bench_aead_decrypt, 64, 100000 );
	measure( "aead decrypt  256B", bench_aead_decrypt, 256, 100000 );
	measure( "aead decrypt  1KiB", bench_aead_decrypt, 1024, 50000 );
	measure( "aead decrypt  4KiB", bench_aead_decrypt, 4096, 20000 );
	measure( "aead decrypt  64KiB", bench_aead_decrypt, 65536, 2000 );
	measure( "aead decrypt  1MiB", bench_aead_decrypt, 1048576, 100 );

	std::printf( "\ndone.\n" );
	return 0;
}
