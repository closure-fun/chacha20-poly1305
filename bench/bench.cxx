#include "chacha20_poly1305.hxx"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#if defined( CCP_BENCH_OPENSSL )
	#include <openssl/evp.h>
	#include <openssl/opensslv.h>
#endif

#if defined( CCP_BENCH_SODIUM )
	#include <sodium.h>
#endif

#if defined( _WIN32 )
	#include <intrin.h>
#endif

namespace
{
	constexpr std::size_t reps = 7;

	const std::uint8_t bench_key_bytes[ 32 ]   = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
	const std::uint8_t bench_nonce_bytes[ 12 ] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
	const std::uint8_t bench_aad[ 12 ]		   = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

	const auto bench_key   = aead::key_t::from_span( std::span< const std::uint8_t >( bench_key_bytes, 32 ) );
	const auto bench_nonce = aead::nonce_t::from_span( std::span< const std::uint8_t >( bench_nonce_bytes, 12 ) );

	bool g_markdown					   = false;
	bool g_self_ok					   = true;
	[[maybe_unused]] bool g_openssl_ok = true;
	[[maybe_unused]] bool g_sodium_ok  = true;

	struct result_t
	{
		double mib_per_sec { };
		double ns_per_op { };
		double min_ns { };
		double max_ns { };
		bool ok { };
	};

	auto fmt_mib( double mib ) -> std::string
	{
		char buffer[ 48 ];
		std::snprintf( buffer, sizeof( buffer ), "%.1f MiB/s", mib );
		return buffer;
	}

	auto fmt_time( double ns ) -> std::string
	{
		char buffer[ 48 ];
		if ( ns < 1000.0 )
			std::snprintf( buffer, sizeof( buffer ), "%.0f ns/op", ns );
		else if ( ns < 1000000.0 )
			std::snprintf( buffer, sizeof( buffer ), "%.2f us/op", ns / 1000.0 );
		else
			std::snprintf( buffer, sizeof( buffer ), "%.2f ms/op", ns / 1000000.0 );
		return buffer;
	}

	auto fmt_time_spread( const result_t& r ) -> std::string
	{
		char buffer[ 96 ];
		if ( r.ns_per_op < 1000.0 )
			std::snprintf( buffer, sizeof( buffer ), "%.0f ns/op [%.0f..%.0f]", r.ns_per_op, r.min_ns, r.max_ns );
		else if ( r.ns_per_op < 1000000.0 )
			std::snprintf( buffer, sizeof( buffer ), "%.2f us/op [%.2f..%.2f]", r.ns_per_op / 1000.0, r.min_ns / 1000.0, r.max_ns / 1000.0 );
		else
			std::snprintf( buffer, sizeof( buffer ), "%.2f ms/op [%.2f..%.2f]", r.ns_per_op / 1000000.0, r.min_ns / 1000000.0, r.max_ns / 1000000.0 );
		return buffer;
	}

	struct environment_t
	{
		std::string cpu;
		std::string compiler;
		std::string os;
		std::string flags;
	};

	auto query_environment( ) -> environment_t
	{
		environment_t env;

#if defined( _WIN32 )
		env.os = "Windows x64";
		std::int32_t regs[ 4 ] { };
		char brand[ 49 ] { };
		__cpuid( regs, 0x80000000 );
		if ( static_cast< std::uint32_t >( regs[ 0 ] ) >= 0x80000004 )
		{
			for ( unsigned leaf = 0; leaf < 3; ++leaf )
			{
				__cpuid( regs, static_cast< std::int32_t >( 0x80000002 + leaf ) );
				std::memcpy( brand + leaf * 16, regs, 16 );
			}
			env.cpu = brand;
		}
#else
		env.os = "posix";
#endif
		while ( !env.cpu.empty( ) && env.cpu.back( ) == ' ' )
			env.cpu.pop_back( );

#if defined( __clang__ )
		env.compiler = "Clang " + std::to_string( __clang_major__ ) + "." + std::to_string( __clang_minor__ );
#elif defined( __GNUC__ )
		env.compiler = "GCC " + std::to_string( __GNUC__ ) + "." + std::to_string( __GNUC_MINOR__ );
#elif defined( _MSC_VER )
		env.compiler = "MSVC " + std::to_string( _MSC_VER );
#endif

#if defined( CCP_BENCH_FLAGS )
		env.flags = CCP_BENCH_FLAGS;
#else
		env.flags = "unrecorded";
#endif

		return env;
	}

	auto resolved_backend( ) -> std::string
	{
#if defined( CCP_X86_SIMD )
		if ( aead::detail::probe_avx512f( ) )
			return "avx-512";
		if ( aead::detail::probe_avx2( ) )
			return "avx2";
		return "sse2";
#elif defined( CCP_NEON_ENABLED )
		return "neon";
#else
		return "scalar";
#endif
	}

	auto measure( void ( *fn )( const std::uint8_t*, std::size_t, std::size_t ), std::size_t size, std::size_t ops ) -> result_t
	{
		const std::vector< std::uint8_t > data( size, 0xAB );

		fn( data.data( ), size, ops / 8 + 1 );

		std::vector< double > ns;
		ns.reserve( reps );
		for ( std::size_t rep = 0; rep < reps; ++rep )
		{
			const auto start = std::chrono::steady_clock::now( );
			fn( data.data( ), size, ops );
			const auto end = std::chrono::steady_clock::now( );

			const double secs = std::chrono::duration< double >( end - start ).count( );
			if ( secs > 0.0 )
				ns.push_back( secs * 1e9 / static_cast< double >( ops ) );
		}

		if ( ns.empty( ) )
			return { };

		std::vector< double > sorted = ns;
		std::sort( sorted.begin( ), sorted.end( ) );

		result_t out;
		out.ok			= true;
		out.ns_per_op	= sorted[ sorted.size( ) / 2 ];
		out.min_ns		= sorted.front( );
		out.max_ns		= sorted.back( );
		out.mib_per_sec = static_cast< double >( size ) / ( out.ns_per_op * 1e-9 ) / ( 1024.0 * 1024.0 );
		return out;
	}

	auto this_chacha( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > out;
		out.resize( size );
		for ( std::size_t idx = 0; idx < ops; ++idx )
			aead::chacha20::xor_stream( out, std::span< const std::uint8_t >( data, size ), bench_key, bench_nonce, 1 );
	}

	auto this_poly( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		for ( std::size_t idx = 0; idx < ops; ++idx )
			( void )aead::poly1305::mac( std::span< const std::uint8_t >( data, size ), bench_key );
	}

	auto this_aead_encrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		ct.resize( size );
		for ( std::size_t idx = 0; idx < ops; ++idx )
			( void )aead::encrypt( ct, std::span< const std::uint8_t >( data, size ), bench_aad, bench_key, bench_nonce );
	}

	auto this_aead_decrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		static std::vector< std::uint8_t > pt;
		ct.resize( size );
		pt.resize( size );
		const auto tag = aead::encrypt( ct, std::span< const std::uint8_t >( data, size ), bench_aad, bench_key, bench_nonce );
		for ( std::size_t idx = 0; idx < ops; ++idx )
			( void )aead::decrypt( pt, ct, bench_aad, bench_key, bench_nonce, tag );
	}

#if defined( CCP_BENCH_OPENSSL )

	auto ossl_chacha( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > out;
		out.resize( size );

		std::uint8_t iv[ 16 ] { };
		iv[ 0 ] = 1;
		std::memcpy( iv + 4, bench_nonce_bytes, 12 );

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
		for ( std::size_t idx = 0; idx < ops; ++idx )
		{
			int len = 0;
			EVP_EncryptInit_ex( ctx, EVP_chacha20( ), nullptr, bench_key_bytes, iv );
			EVP_EncryptUpdate( ctx, out.data( ), &len, data, static_cast< int >( size ) );
			EVP_EncryptFinal_ex( ctx, out.data( ) + len, &len );
		}
		EVP_CIPHER_CTX_free( ctx );
	}

	auto ossl_poly( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		EVP_MAC* mac	 = EVP_MAC_fetch( nullptr, "POLY1305", nullptr );
		EVP_MAC_CTX* ctx = EVP_MAC_CTX_new( mac );

		std::uint8_t tag[ 16 ];
		std::size_t tag_len = 16;
		for ( std::size_t idx = 0; idx < ops; ++idx )
		{
			EVP_MAC_init( ctx, bench_key_bytes, 32, nullptr );
			EVP_MAC_update( ctx, data, size );
			EVP_MAC_final( ctx, tag, &tag_len, sizeof( tag ) );
		}

		EVP_MAC_CTX_free( ctx );
		EVP_MAC_free( mac );
	}

	auto ossl_aead_encrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		ct.resize( size );

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
		std::uint8_t tag[ 16 ];
		for ( std::size_t idx = 0; idx < ops; ++idx )
		{
			int len = 0;
			EVP_EncryptInit_ex( ctx, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
			EVP_EncryptUpdate( ctx, nullptr, &len, bench_aad, sizeof( bench_aad ) );
			EVP_EncryptUpdate( ctx, ct.data( ), &len, data, static_cast< int >( size ) );
			EVP_EncryptFinal_ex( ctx, ct.data( ) + len, &len );
			EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag );
		}
		EVP_CIPHER_CTX_free( ctx );
	}

	auto ossl_aead_decrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		static std::vector< std::uint8_t > pt;
		ct.resize( size );
		pt.resize( size );

		std::uint8_t tag[ 16 ];
		EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new( );
		int len				= 0;
		EVP_EncryptInit_ex( enc, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
		EVP_EncryptUpdate( enc, nullptr, &len, bench_aad, sizeof( bench_aad ) );
		EVP_EncryptUpdate( enc, ct.data( ), &len, data, static_cast< int >( size ) );
		EVP_EncryptFinal_ex( enc, ct.data( ) + len, &len );
		EVP_CIPHER_CTX_ctrl( enc, EVP_CTRL_AEAD_GET_TAG, 16, tag );
		EVP_CIPHER_CTX_free( enc );

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
		for ( std::size_t idx = 0; idx < ops; ++idx )
		{
			EVP_DecryptInit_ex( ctx, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
			EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag );
			EVP_DecryptUpdate( ctx, nullptr, &len, bench_aad, sizeof( bench_aad ) );
			EVP_DecryptUpdate( ctx, pt.data( ), &len, ct.data( ), static_cast< int >( size ) );
			( void )EVP_DecryptFinal_ex( ctx, pt.data( ) + len, &len );
		}
		EVP_CIPHER_CTX_free( ctx );
	}

#endif

#if defined( CCP_BENCH_SODIUM )

	auto sodium_chacha( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > out;
		out.resize( size );
		for ( std::size_t idx = 0; idx < ops; ++idx )
			crypto_stream_chacha20_ietf_xor( out.data( ), data, size, bench_nonce_bytes, bench_key_bytes );
	}

	auto sodium_poly( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		std::uint8_t tag[ 16 ];
		for ( std::size_t idx = 0; idx < ops; ++idx )
			crypto_onetimeauth_poly1305( tag, data, size, bench_key_bytes );
	}

	auto sodium_aead_encrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		ct.resize( size + 16 );
		unsigned long long clen = 0;
		for ( std::size_t idx = 0; idx < ops; ++idx )
			crypto_aead_chacha20poly1305_ietf_encrypt( ct.data( ), &clen, data, size, bench_aad, sizeof( bench_aad ), nullptr, bench_nonce_bytes, bench_key_bytes );
	}

	auto sodium_aead_decrypt( const std::uint8_t* data, std::size_t size, std::size_t ops ) -> void
	{
		static std::vector< std::uint8_t > ct;
		static std::vector< std::uint8_t > pt;
		ct.resize( size + 16 );
		pt.resize( size );

		unsigned long long clen = 0;
		crypto_aead_chacha20poly1305_ietf_encrypt( ct.data( ), &clen, data, size, bench_aad, sizeof( bench_aad ), nullptr, bench_nonce_bytes, bench_key_bytes );

		unsigned long long mlen = 0;
		for ( std::size_t idx = 0; idx < ops; ++idx )
			( void )crypto_aead_chacha20poly1305_ietf_decrypt( pt.data( ), &mlen, nullptr, ct.data( ), clen, bench_aad, sizeof( bench_aad ), bench_nonce_bytes, bench_key_bytes );
	}

#endif

	auto verify_equivalence( ) -> void
	{
		for ( std::size_t size : { std::size_t( 64 ), std::size_t( 114 ), std::size_t( 1024 ), std::size_t( 4096 ) } )
		{
			std::vector< std::uint8_t > plain( size );
			for ( std::size_t idx = 0; idx < size; ++idx )
				plain[ idx ] = static_cast< std::uint8_t >( idx * 31 + 7 );

			std::vector< std::uint8_t > ref_ct( size );
			const auto ref_tag = aead::encrypt( ref_ct, plain, bench_aad, bench_key, bench_nonce );
			( void )ref_tag;

#if defined( CCP_BENCH_OPENSSL )
			{
				std::vector< std::uint8_t > ct( size );
				std::uint8_t tag[ 16 ];
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
				int len				= 0;
				EVP_EncryptInit_ex( ctx, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
				EVP_EncryptUpdate( ctx, nullptr, &len, bench_aad, sizeof( bench_aad ) );
				EVP_EncryptUpdate( ctx, ct.data( ), &len, plain.data( ), static_cast< int >( size ) );
				EVP_EncryptFinal_ex( ctx, ct.data( ) + len, &len );
				EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag );
				EVP_CIPHER_CTX_free( ctx );

				if ( std::memcmp( ct.data( ), ref_ct.data( ), size ) != 0 || std::memcmp( tag, ref_tag.bytes.data( ), 16 ) != 0 )
					g_openssl_ok = false;
			}
#endif

#if defined( CCP_BENCH_SODIUM )
			{
				std::vector< std::uint8_t > ct( size + 16 );
				unsigned long long clen = 0;
				crypto_aead_chacha20poly1305_ietf_encrypt( ct.data( ), &clen, plain.data( ), size, bench_aad, sizeof( bench_aad ), nullptr, bench_nonce_bytes, bench_key_bytes );

				if ( clen != size + 16 || std::memcmp( ct.data( ), ref_ct.data( ), size ) != 0 || std::memcmp( ct.data( ) + size, ref_tag.bytes.data( ), 16 ) != 0 )
					g_sodium_ok = false;
			}
#endif
		}

		{
			std::vector< std::uint8_t > plain( 300 );
			for ( std::size_t idx = 0; idx < plain.size( ); ++idx )
				plain[ idx ] = static_cast< std::uint8_t >( idx );

			std::vector< std::uint8_t > ct( 300 );
			auto tag = aead::encrypt( ct, plain, bench_aad, bench_key, bench_nonce );
			tag.bytes[ 15 ] ^= 0x80;

			std::vector< std::uint8_t > pt( 300 );
			if ( aead::decrypt( pt, ct, bench_aad, bench_key, bench_nonce, tag ) )
				g_self_ok = false;

#if defined( CCP_BENCH_OPENSSL )
			{
				std::vector< std::uint8_t > oct( 300 );
				std::vector< std::uint8_t > opt( 300 );
				std::uint8_t otag[ 16 ];
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
				int len				= 0;
				EVP_EncryptInit_ex( ctx, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
				EVP_EncryptUpdate( ctx, nullptr, &len, bench_aad, sizeof( bench_aad ) );
				EVP_EncryptUpdate( ctx, oct.data( ), &len, plain.data( ), 300 );
				EVP_EncryptFinal_ex( ctx, oct.data( ) + len, &len );
				EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_GET_TAG, 16, otag );
				otag[ 15 ] ^= 0x80;
				EVP_DecryptInit_ex( ctx, EVP_chacha20_poly1305( ), nullptr, bench_key_bytes, bench_nonce_bytes );
				EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_AEAD_SET_TAG, 16, otag );
				int len2 = 0;
				EVP_DecryptUpdate( ctx, nullptr, &len2, bench_aad, sizeof( bench_aad ) );
				EVP_DecryptUpdate( ctx, opt.data( ), &len2, oct.data( ), 300 );
				if ( EVP_DecryptFinal_ex( ctx, opt.data( ) + len2, &len2 ) > 0 )
					g_openssl_ok = false;
				EVP_CIPHER_CTX_free( ctx );
			}
#endif

#if defined( CCP_BENCH_SODIUM )
			{
				std::vector< std::uint8_t > sct( 316 );
				std::vector< std::uint8_t > spt( 300 );
				unsigned long long clen = 0, mlen = 0;
				crypto_aead_chacha20poly1305_ietf_encrypt( sct.data( ), &clen, plain.data( ), 300, bench_aad, sizeof( bench_aad ), nullptr, bench_nonce_bytes, bench_key_bytes );
				sct[ clen - 1 ] ^= 0x80;
				if ( crypto_aead_chacha20poly1305_ietf_decrypt( spt.data( ), &mlen, nullptr, sct.data( ), clen, bench_aad, sizeof( bench_aad ), bench_nonce_bytes, bench_key_bytes ) == 0 )
					g_sodium_ok = false;
			}
#endif
		}

		{
			std::vector< std::uint8_t > data( 1024, 0x5a );
			std::vector< std::uint8_t > ref( 1024 );
			aead::chacha20::xor_stream( ref, data, bench_key, bench_nonce, 1 );

#if defined( CCP_BENCH_OPENSSL )
			{
				std::vector< std::uint8_t > out( 1024 );
				std::uint8_t iv[ 16 ] { };
				iv[ 0 ] = 1;
				std::memcpy( iv + 4, bench_nonce_bytes, 12 );
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new( );
				int len				= 0;
				EVP_EncryptInit_ex( ctx, EVP_chacha20( ), nullptr, bench_key_bytes, iv );
				EVP_EncryptUpdate( ctx, out.data( ), &len, data.data( ), 1024 );
				EVP_EncryptFinal_ex( ctx, out.data( ) + len, &len );
				EVP_CIPHER_CTX_free( ctx );
				if ( std::memcmp( out.data( ), ref.data( ), 1024 ) != 0 )
					g_openssl_ok = false;
			}
#endif

#if defined( CCP_BENCH_SODIUM )
			{
				std::vector< std::uint8_t > ref0( 1024 );
				std::vector< std::uint8_t > out( 1024 );
				aead::chacha20::xor_stream( ref0, data, bench_key, bench_nonce, 0 );
				crypto_stream_chacha20_ietf_xor( out.data( ), data.data( ), 1024, bench_nonce_bytes, bench_key_bytes );
				if ( std::memcmp( out.data( ), ref0.data( ), 1024 ) != 0 )
					g_sodium_ok = false;
			}
#endif
		}

		{
			std::vector< std::uint8_t > data( 512 );
			for ( std::size_t idx = 0; idx < data.size( ); ++idx )
				data[ idx ] = static_cast< std::uint8_t >( idx * 3 );

			const auto ref_tag = aead::poly1305::mac( data, bench_key );
			( void )ref_tag;

#if defined( CCP_BENCH_OPENSSL )
			{
				EVP_MAC* mac	 = EVP_MAC_fetch( nullptr, "POLY1305", nullptr );
				EVP_MAC_CTX* ctx = EVP_MAC_CTX_new( mac );
				std::uint8_t tag[ 16 ];
				std::size_t tag_len = 16;
				EVP_MAC_init( ctx, bench_key_bytes, 32, nullptr );
				EVP_MAC_update( ctx, data.data( ), data.size( ) );
				EVP_MAC_final( ctx, tag, &tag_len, sizeof( tag ) );
				EVP_MAC_CTX_free( ctx );
				EVP_MAC_free( mac );
				if ( std::memcmp( tag, ref_tag.bytes.data( ), 16 ) != 0 )
					g_openssl_ok = false;
			}
#endif

#if defined( CCP_BENCH_SODIUM )
			{
				std::uint8_t tag[ 16 ];
				crypto_onetimeauth_poly1305( tag, data.data( ), data.size( ), bench_key_bytes );
				if ( std::memcmp( tag, ref_tag.bytes.data( ), 16 ) != 0 )
					g_sodium_ok = false;
			}
#endif
		}
	}
}

auto main( int argc, char** argv ) -> int
{
	for ( int idx = 1; idx < argc; ++idx )
		if ( std::strcmp( argv[ idx ], "--markdown" ) == 0 )
			g_markdown = true;

#if defined( CCP_BENCH_SODIUM )
	if ( sodium_init( ) < 0 )
	{
		std::fprintf( stderr, "sodium_init failed\n" );
		return 1;
	}
#endif

	verify_equivalence( );

	if ( !g_self_ok )
	{
		std::fprintf( stderr, "this library accepted a tampered authentication tag, aborting\n" );
		return 1;
	}

	const auto env	   = query_environment( );
	const auto backend = resolved_backend( );

	if ( !g_markdown )
	{
		std::printf( "chacha20-poly1305 benchmark\n\n" );
		std::printf( "cpu:      %s\n", env.cpu.c_str( ) );
		std::printf( "compiler: %s ( %s )\n", env.compiler.c_str( ), env.flags.c_str( ) );
		std::printf( "os:       %s\n", env.os.c_str( ) );
		std::printf( "backends: this library %s", backend.c_str( ) );
#if defined( CCP_BENCH_OPENSSL )
		std::printf( " | openssl %s", OPENSSL_VERSION_TEXT );
		if ( !g_openssl_ok )
			std::printf( " ( output mismatch, excluded )" );
#else
		std::printf( " | openssl not built in" );
#endif
#if defined( CCP_BENCH_SODIUM )
		std::printf( " | libsodium %s", sodium_version_string( ) );
		if ( !g_sodium_ok )
			std::printf( " ( output mismatch, excluded )" );
#else
		std::printf( " | libsodium not built in" );
#endif
		std::printf( "\n" );
		std::printf( "method:   median of %zu reps, steady_clock, identical inputs and aad, preallocated reused\n", reps );
		std::printf( "          buffers, per-op key setup and authentication included, allocation excluded\n\n" );
	}
	else
	{
		std::printf( "## benchmark environment\n\n" );
		std::printf( "- cpu: %s\n", env.cpu.c_str( ) );
		std::printf( "- compiler: %s ( %s )\n", env.compiler.c_str( ), env.flags.c_str( ) );
		std::printf( "- os: %s\n", env.os.c_str( ) );
		std::printf( "- backends: this library %s", backend.c_str( ) );
#if defined( CCP_BENCH_OPENSSL )
		std::printf( ", openssl %s", OPENSSL_VERSION_TEXT );
		if ( !g_openssl_ok )
			std::printf( " ( output mismatch, excluded from results )" );
#else
		std::printf( ", openssl not built in ( run with CHACHA20_POLY1305_BENCH_EXTERNAL )" );
#endif
#if defined( CCP_BENCH_SODIUM )
		std::printf( ", libsodium %s", sodium_version_string( ) );
		if ( !g_sodium_ok )
			std::printf( " ( output mismatch, excluded from results )" );
#else
		std::printf( ", libsodium not built in ( run with CHACHA20_POLY1305_BENCH_EXTERNAL )" );
#endif
		std::printf( "\n" );
		std::printf( "- method: median of %zu repetitions, monotonic steady clock, identical inputs and aad,\n", reps );
		std::printf( "  preallocated reused buffers, per-operation key setup and authentication included, allocation excluded\n" );
		std::printf( "- before timing, ciphertext, tag, raw stream and mac equivalence against this library was\n" );
		std::printf( "  verified, and every library rejected a tampered authentication tag\n" );
	}

	struct size_ops_t
	{
		std::size_t size;
		std::size_t ops;
	};

	const size_ops_t sizes[] = {
		{ 64, 200000 },
		{ 256, 100000 },
		{ 1024, 50000 },
		{ 4096, 20000 },
		{ 65536, 2000 },
		{ 1048576, 100 },
	};

	const char* size_labels[] = { "64 B", "256 B", "1 KiB", "4 KiB", "64 KiB", "1 MiB" };

	struct workload_def_t
	{
		const char* label;
		void ( *mine )( const std::uint8_t*, std::size_t, std::size_t );
#if defined( CCP_BENCH_OPENSSL )
		void ( *openssl )( const std::uint8_t*, std::size_t, std::size_t );
#endif
#if defined( CCP_BENCH_SODIUM )
		void ( *sodium )( const std::uint8_t*, std::size_t, std::size_t );
#endif
	};

	const workload_def_t workloads[] = {
		{
			"aead encrypt",
			this_aead_encrypt,
#if defined( CCP_BENCH_OPENSSL )
			ossl_aead_encrypt,
#endif
#if defined( CCP_BENCH_SODIUM )
			sodium_aead_encrypt,
#endif
		},
		{
			"aead decrypt",
			this_aead_decrypt,
#if defined( CCP_BENCH_OPENSSL )
			ossl_aead_decrypt,
#endif
#if defined( CCP_BENCH_SODIUM )
			sodium_aead_decrypt,
#endif
		},
		{
			"chacha20",
			this_chacha,
#if defined( CCP_BENCH_OPENSSL )
			ossl_chacha,
#endif
#if defined( CCP_BENCH_SODIUM )
			sodium_chacha,
#endif
		},
		{
			"poly1305",
			this_poly,
#if defined( CCP_BENCH_OPENSSL )
			ossl_poly,
#endif
#if defined( CCP_BENCH_SODIUM )
			sodium_poly,
#endif
		},
	};

	for ( const auto& wl : workloads )
	{
		if ( !g_markdown )
		{
			std::printf( "\n%s\n", wl.label );
			std::printf( "  %-8s %-24s", "size", "this library" );
#if defined( CCP_BENCH_OPENSSL )
			std::printf( " %-32s", "openssl" );
#else
			std::printf( " %-32s", "openssl ( n/a )" );
#endif
#if defined( CCP_BENCH_SODIUM )
			std::printf( " %-32s\n", "libsodium" );
#else
			std::printf( " %-32s\n", "libsodium ( n/a )" );
#endif
		}
		else
		{
			std::printf( "\n### %s\n\n", wl.label );
			std::printf( "| workload | this library | openssl | libsodium | relative result |\n" );
			std::printf( "|---|---|---|---|---|\n" );
		}

		for ( std::size_t idx = 0; idx < 6; ++idx )
		{
			const auto [ size, ops ] = sizes[ idx ];

			const result_t mine = measure( wl.mine, size, ops );
#if defined( CCP_BENCH_OPENSSL )
			const result_t ossl = g_openssl_ok ? measure( wl.openssl, size, ops ) : result_t { };
#else
			const result_t ossl = result_t { };
#endif
#if defined( CCP_BENCH_SODIUM )
			const result_t sodium = g_sodium_ok ? measure( wl.sodium, size, ops ) : result_t { };
#else
			const result_t sodium = result_t { };
#endif

			if ( !g_markdown )
			{
				auto cell = []( const result_t& r ) -> std::string {
					if ( !r.ok )
						return "n/a";
					return fmt_mib( r.mib_per_sec ) + " " + fmt_time( r.ns_per_op );
				};
				std::printf( "  %-8s %-24s %-32s %-32s\n", size_labels[ idx ], cell( mine ).c_str( ), cell( ossl ).c_str( ), cell( sodium ).c_str( ) );
			}
			else
			{
				auto cell = []( const result_t& r ) -> std::string {
					if ( !r.ok )
						return "unavailable";
					return fmt_mib( r.mib_per_sec ) + ", " + fmt_time_spread( r );
				};

				std::string rel = "unmeasured";
				if ( mine.ok )
				{
					const char* best_name = nullptr;
					double best			  = 0.0;
					if ( ossl.ok && ossl.mib_per_sec > best )
					{
						best	  = ossl.mib_per_sec;
						best_name = "openssl";
					}
					if ( sodium.ok && sodium.mib_per_sec > best )
					{
						best	  = sodium.mib_per_sec;
						best_name = "libsodium";
					}
					if ( best_name )
					{
						const double ratio = mine.mib_per_sec / best;
						char buffer[ 64 ];
						if ( ratio >= 1.05 )
							std::snprintf( buffer, sizeof( buffer ), "%.2fx faster than %s", ratio, best_name );
						else if ( ratio <= 0.95 )
							std::snprintf( buffer, sizeof( buffer ), "%.2fx slower than %s", 1.0 / ratio, best_name );
						else
							std::snprintf( buffer, sizeof( buffer ), "comparable to %s", best_name );
						rel = buffer;
					}
				}

				std::printf( "| %s, %s | %s | %s | %s | %s |\n",
					wl.label, size_labels[ idx ],
					cell( mine ).c_str( ),
					cell( ossl ).c_str( ),
					cell( sodium ).c_str( ),
					rel.c_str( ) );
			}
		}
	}

	if ( !g_markdown )
		std::printf( "\nevery ns/op is the median of %zu repetitions, each repetition times a full batch of ops on a\n"
					 "monotonic clock, spread = min..max across repetitions\n",
			reps );

	return 0;
}
