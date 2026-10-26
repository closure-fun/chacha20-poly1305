#ifndef CHACHA20_POLY1305_DETAIL_HXX
#define CHACHA20_POLY1305_DETAIL_HXX

#include <cstddef>
#include <cstdint>

#if defined( __x86_64__ ) || defined( _M_X64 )
	#define CCP_X86_64 1
#elif defined( __aarch64__ ) || defined( _M_ARM64 ) || defined( _M_ARM64EC )
	#define CCP_ARM64 1
#endif

#if defined( CCP_X86_64 ) && !defined( CCP_DISABLE_SIMD )
	#define CCP_X86_SIMD 1

	#if !defined( CCP_DISABLE_AVX512 )
		#define CCP_AVX512_ENABLED 1
	#endif
#elif defined( CCP_ARM64 ) && !defined( CCP_DISABLE_SIMD )
	#define CCP_NEON_ENABLED 1
#endif

namespace aead
{
	namespace detail
	{
		struct poly_state_t
		{
			std::uint32_t h[ 5 ] { };
			std::uint32_t r[ 5 ] { };
			std::uint32_t s[ 4 ] { };

			alignas( 64 ) std::uint32_t powers[ 8 ][ 5 ];
			alignas( 64 ) std::uint8_t buffer[ 64 ];

			std::size_t buffered { };

			bool use_avx2 { };
			bool powers_ready { };
		};

		using chacha_fn_t = void ( * )( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept;

		constexpr auto load_le32( const std::uint8_t* p ) noexcept -> std::uint32_t
		{
			return static_cast< std::uint32_t >( p[ 0 ] ) | ( static_cast< std::uint32_t >( p[ 1 ] ) << 8 ) | ( static_cast< std::uint32_t >( p[ 2 ] ) << 16 ) | ( static_cast< std::uint32_t >( p[ 3 ] ) << 24 );
		}

		constexpr auto load_le64( const std::uint8_t* p ) noexcept -> std::uint64_t
		{
			return static_cast< std::uint64_t >( load_le32( p ) ) | ( static_cast< std::uint64_t >( load_le32( p + 4 ) ) << 32 );
		}

		constexpr auto store_le32( std::uint8_t* p, std::uint32_t v ) noexcept -> void
		{
			p[ 0 ] = static_cast< std::uint8_t >( v );
			p[ 1 ] = static_cast< std::uint8_t >( v >> 8 );
			p[ 2 ] = static_cast< std::uint8_t >( v >> 16 );
			p[ 3 ] = static_cast< std::uint8_t >( v >> 24 );
		}

		constexpr auto store_le64( std::uint8_t* p, std::uint64_t v ) noexcept -> void
		{
			store_le32( p, static_cast< std::uint32_t >( v ) );
			store_le32( p + 4, static_cast< std::uint32_t >( v >> 32 ) );
		}

		constexpr auto pad16( std::size_t length ) noexcept -> std::size_t
		{
			return ( 16 - ( length % 16 ) ) % 16;
		}

		auto secure_zero( void* ptr, std::size_t length ) noexcept -> void;

		auto chacha_scalar( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void;

		auto poly_init_state( poly_state_t& st, const std::uint8_t* key ) noexcept -> void;
		auto poly_absorb( poly_state_t& st, const std::uint8_t* data, std::size_t length ) noexcept -> void;
		auto poly_finish( poly_state_t& st, std::uint8_t* tag ) noexcept -> void;

		auto poly_mul_reduce( std::uint32_t ( &out )[ 5 ], const std::uint32_t ( &a )[ 5 ], const std::uint32_t ( &b )[ 5 ] ) noexcept -> void;

#if defined( CCP_X86_SIMD )
		auto chacha_sse2( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void;
		auto chacha_avx2( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void;
		auto probe_avx2( ) -> bool;
		auto poly_blocks_avx2( std::uint32_t ( &h )[ 5 ], const std::uint32_t ( &powers )[ 8 ][ 5 ], const std::uint8_t* message, std::size_t n64 ) noexcept -> void;
	#if defined( CCP_AVX512_ENABLED )
		auto chacha_avx512( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void;
		auto probe_avx512f( ) -> bool;
	#endif
#elif defined( CCP_NEON_ENABLED )
		auto chacha_neon( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void;
#endif

		auto resolve_chacha( ) noexcept -> chacha_fn_t;
	}
}

#endif
