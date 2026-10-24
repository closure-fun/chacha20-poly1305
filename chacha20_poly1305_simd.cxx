#include "chacha20_poly1305_detail.hxx"

#if defined( CCP_X86_SIMD )

	#include <immintrin.h>

	#if defined( _WIN32 )
		#include <intrin.h>
	#endif

	#if defined( _MSC_VER ) && !defined( __clang__ )
		#define CCP_TARGET( ... )
	#else
		#define CCP_TARGET( ... ) __attribute__( ( target( __VA_ARGS__ ) ) )
	#endif

namespace aead
{
	namespace detail
	{
		constexpr std::uint32_t limb_mask = 0x03ffffff;

	#if defined( _WIN32 )

		auto probe_avx2( ) -> bool
		{
			std::int32_t regs[ 4 ];
			__cpuidex( regs, 1, 0 );

			if ( ( regs[ 2 ] & ( 1 << 27 ) ) == 0 || ( regs[ 2 ] & ( 1 << 28 ) ) == 0 )
				return false;

			if ( ( _xgetbv( 0 ) & 0x6 ) != 0x6 )
				return false;

			__cpuidex( regs, 7, 0 );
			return ( regs[ 1 ] & ( 1 << 5 ) ) != 0;
		}

		auto probe_avx512f( ) -> bool
		{
			std::int32_t regs[ 4 ];
			__cpuidex( regs, 1, 0 );

			if ( ( regs[ 2 ] & ( 1 << 27 ) ) == 0 || ( regs[ 2 ] & ( 1 << 28 ) ) == 0 )
				return false;

			if ( ( _xgetbv( 0 ) & 0xe6 ) != 0xe6 )
				return false;

			__cpuidex( regs, 7, 0 );
			return ( regs[ 1 ] & ( 1 << 16 ) ) != 0;
		}

	#else

		auto probe_avx2( ) -> bool
		{
			return __builtin_cpu_supports( "avx2" );
		}

		auto probe_avx512f( ) -> bool
		{
			return __builtin_cpu_supports( "avx512f" );
		}

	#endif

		inline auto rotl16_sse2( __m128i v ) noexcept -> __m128i
		{
			return _mm_shufflehi_epi16( _mm_shufflelo_epi16( v, 0xB1 ), 0xB1 );
		}

		inline auto rotl_sse2( __m128i v, unsigned n ) noexcept -> __m128i
		{
			return _mm_or_si128( _mm_slli_epi32( v, n ), _mm_srli_epi32( v, 32 - n ) );
		}

		inline auto qr_sse2( __m128i& a, __m128i& b, __m128i& c, __m128i& d ) noexcept -> void
		{
			a = _mm_add_epi32( a, b );
			d = _mm_xor_si128( d, a );
			d = rotl16_sse2( d );

			c = _mm_add_epi32( c, d );
			b = _mm_xor_si128( b, c );
			b = rotl_sse2( b, 12 );

			a = _mm_add_epi32( a, b );
			d = _mm_xor_si128( d, a );
			d = rotl_sse2( d, 8 );

			c = _mm_add_epi32( c, d );
			b = _mm_xor_si128( b, c );
			b = rotl_sse2( b, 7 );
		}

		auto chacha_sse2( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void
		{
			std::uint32_t state[ 16 ];

			state[ 0 ] = 0x61707865;
			state[ 1 ] = 0x3320646e;
			state[ 2 ] = 0x79622d32;
			state[ 3 ] = 0x6b206574;

			for ( unsigned idx = 0; idx < 8; ++idx )
				state[ 4 + idx ] = load_le32( key + idx * 4 );

			state[ 12 ] = counter;
			state[ 13 ] = load_le32( nonce );
			state[ 14 ] = load_le32( nonce + 4 );
			state[ 15 ] = load_le32( nonce + 8 );

			while ( length >= 256 )
			{
				__m128i v[ 16 ];

				for ( unsigned idx = 0; idx < 16; ++idx )
					v[ idx ] = _mm_set1_epi32( static_cast< int >( state[ idx ] ) );

				v[ 12 ] = _mm_setr_epi32( static_cast< int >( state[ 12 ] ), static_cast< int >( state[ 12 ] + 1 ), static_cast< int >( state[ 12 ] + 2 ), static_cast< int >( state[ 12 ] + 3 ) );

				for ( int round = 0; round < 10; ++round )
				{
					qr_sse2( v[ 0 ], v[ 4 ], v[ 8 ], v[ 12 ] );
					qr_sse2( v[ 1 ], v[ 5 ], v[ 9 ], v[ 13 ] );
					qr_sse2( v[ 2 ], v[ 6 ], v[ 10 ], v[ 14 ] );
					qr_sse2( v[ 3 ], v[ 7 ], v[ 11 ], v[ 15 ] );
					qr_sse2( v[ 0 ], v[ 5 ], v[ 10 ], v[ 15 ] );
					qr_sse2( v[ 1 ], v[ 6 ], v[ 11 ], v[ 12 ] );
					qr_sse2( v[ 2 ], v[ 7 ], v[ 8 ], v[ 13 ] );
					qr_sse2( v[ 3 ], v[ 4 ], v[ 9 ], v[ 14 ] );
				}

				for ( unsigned idx = 0; idx < 16; ++idx )
				{
					if ( idx != 12 )
						v[ idx ] = _mm_add_epi32( v[ idx ], _mm_set1_epi32( static_cast< int >( state[ idx ] ) ) );
				}

				v[ 12 ] = _mm_add_epi32( v[ 12 ], _mm_setr_epi32( static_cast< int >( state[ 12 ] ), static_cast< int >( state[ 12 ] + 1 ), static_cast< int >( state[ 12 ] + 2 ), static_cast< int >( state[ 12 ] + 3 ) ) );

				for ( unsigned row = 0; row < 4; ++row )
				{
					const __m128i a = _mm_unpacklo_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m128i b = _mm_unpackhi_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m128i c = _mm_unpacklo_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );
					const __m128i d = _mm_unpackhi_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );

					const __m128i blocks[ 4 ] = {
						_mm_unpacklo_epi64( a, c ),
						_mm_unpackhi_epi64( a, c ),
						_mm_unpacklo_epi64( b, d ),
						_mm_unpackhi_epi64( b, d ),
					};

					for ( unsigned blk = 0; blk < 4; ++blk )
					{
						const std::size_t off = blk * 64 + row * 16;
						const __m128i in	  = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off ), _mm_xor_si128( in, blocks[ blk ] ) );
					}
				}

				state[ 12 ] += 4;
				source += 256;
				destination += 256;
				length -= 256;
			}

			if ( length )
				chacha_scalar( destination, source, length, key, nonce, state[ 12 ] );
		}

		CCP_TARGET( "avx2" )
		inline auto rotl16_avx2( __m256i v ) noexcept -> __m256i
		{
			return _mm256_shufflehi_epi16( _mm256_shufflelo_epi16( v, 0xB1 ), 0xB1 );
		}

		CCP_TARGET( "avx2" )
		inline auto rotl8_avx2( __m256i v ) noexcept -> __m256i
		{
			return _mm256_shuffle_epi8( v, _mm256_set_epi8( 14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3 ) );
		}

		CCP_TARGET( "avx2" )
		inline auto rotl_avx2( __m256i v, unsigned n ) noexcept -> __m256i
		{
			return _mm256_or_si256( _mm256_slli_epi32( v, n ), _mm256_srli_epi32( v, 32 - n ) );
		}

		CCP_TARGET( "avx2" )
		inline auto qr_avx2( __m256i& a, __m256i& b, __m256i& c, __m256i& d ) noexcept -> void
		{
			a = _mm256_add_epi32( a, b );
			d = _mm256_xor_si256( d, a );
			d = rotl16_avx2( d );

			c = _mm256_add_epi32( c, d );
			b = _mm256_xor_si256( b, c );
			b = rotl_avx2( b, 12 );

			a = _mm256_add_epi32( a, b );
			d = _mm256_xor_si256( d, a );
			d = rotl8_avx2( d );

			c = _mm256_add_epi32( c, d );
			b = _mm256_xor_si256( b, c );
			b = rotl_avx2( b, 7 );
		}

		CCP_TARGET( "avx2" )
		auto chacha_avx2( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void
		{
			std::uint32_t state[ 16 ];

			state[ 0 ] = 0x61707865;
			state[ 1 ] = 0x3320646e;
			state[ 2 ] = 0x79622d32;
			state[ 3 ] = 0x6b206574;

			for ( unsigned idx = 0; idx < 8; ++idx )
				state[ 4 + idx ] = load_le32( key + idx * 4 );

			state[ 12 ] = counter;
			state[ 13 ] = load_le32( nonce );
			state[ 14 ] = load_le32( nonce + 4 );
			state[ 15 ] = load_le32( nonce + 8 );

			while ( length >= 512 )
			{
				__m256i v[ 16 ];

				for ( unsigned idx = 0; idx < 16; ++idx )
					v[ idx ] = _mm256_set1_epi32( static_cast< int >( state[ idx ] ) );

				v[ 12 ] = _mm256_setr_epi32( static_cast< int >( state[ 12 ] ), static_cast< int >( state[ 12 ] + 1 ), static_cast< int >( state[ 12 ] + 2 ), static_cast< int >( state[ 12 ] + 3 ), static_cast< int >( state[ 12 ] + 4 ), static_cast< int >( state[ 12 ] + 5 ), static_cast< int >( state[ 12 ] + 6 ), static_cast< int >( state[ 12 ] + 7 ) );

				for ( int round = 0; round < 10; ++round )
				{
					qr_avx2( v[ 0 ], v[ 4 ], v[ 8 ], v[ 12 ] );
					qr_avx2( v[ 1 ], v[ 5 ], v[ 9 ], v[ 13 ] );
					qr_avx2( v[ 2 ], v[ 6 ], v[ 10 ], v[ 14 ] );
					qr_avx2( v[ 3 ], v[ 7 ], v[ 11 ], v[ 15 ] );
					qr_avx2( v[ 0 ], v[ 5 ], v[ 10 ], v[ 15 ] );
					qr_avx2( v[ 1 ], v[ 6 ], v[ 11 ], v[ 12 ] );
					qr_avx2( v[ 2 ], v[ 7 ], v[ 8 ], v[ 13 ] );
					qr_avx2( v[ 3 ], v[ 4 ], v[ 9 ], v[ 14 ] );
				}

				for ( unsigned idx = 0; idx < 16; ++idx )
				{
					if ( idx != 12 )
						v[ idx ] = _mm256_add_epi32( v[ idx ], _mm256_set1_epi32( static_cast< int >( state[ idx ] ) ) );
				}

				v[ 12 ] = _mm256_add_epi32( v[ 12 ], _mm256_setr_epi32( static_cast< int >( state[ 12 ] ), static_cast< int >( state[ 12 ] + 1 ), static_cast< int >( state[ 12 ] + 2 ), static_cast< int >( state[ 12 ] + 3 ), static_cast< int >( state[ 12 ] + 4 ), static_cast< int >( state[ 12 ] + 5 ), static_cast< int >( state[ 12 ] + 6 ), static_cast< int >( state[ 12 ] + 7 ) ) );

				for ( unsigned row = 0; row < 4; ++row )
				{
					const __m256i a = _mm256_unpacklo_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m256i b = _mm256_unpackhi_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m256i c = _mm256_unpacklo_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );
					const __m256i d = _mm256_unpackhi_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );

					const __m256i pairs[ 4 ] = {
						_mm256_unpacklo_epi64( a, c ),
						_mm256_unpackhi_epi64( a, c ),
						_mm256_unpacklo_epi64( b, d ),
						_mm256_unpackhi_epi64( b, d ),
					};

					for ( unsigned blk = 0; blk < 4; ++blk )
					{
						const std::size_t off_lo = blk * 64 + row * 16;
						const std::size_t off_hi = ( blk + 4 ) * 64 + row * 16;

						const __m128i ks_lo = _mm256_castsi256_si128( pairs[ blk ] );
						const __m128i ks_hi = _mm256_extracti128_si256( pairs[ blk ], 1 );

						const __m128i in_lo = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off_lo ) );
						const __m128i in_hi = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off_hi ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off_lo ), _mm_xor_si128( in_lo, ks_lo ) );
						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off_hi ), _mm_xor_si128( in_hi, ks_hi ) );
					}
				}

				state[ 12 ] += 8;
				source += 512;
				destination += 512;
				length -= 512;
			}

			if ( length )
				chacha_sse2( destination, source, length, key, nonce, state[ 12 ] );
		}

	#if defined( CCP_AVX512_ENABLED )

		CCP_TARGET( "avx512f" )
		inline auto qr_avx512( __m512i& a, __m512i& b, __m512i& c, __m512i& d ) noexcept -> void
		{
			a = _mm512_add_epi32( a, b );
			d = _mm512_xor_si512( d, a );
			d = _mm512_rol_epi32( d, 16 );

			c = _mm512_add_epi32( c, d );
			b = _mm512_xor_si512( b, c );
			b = _mm512_rol_epi32( b, 12 );

			a = _mm512_add_epi32( a, b );
			d = _mm512_xor_si512( d, a );
			d = _mm512_rol_epi32( d, 8 );

			c = _mm512_add_epi32( c, d );
			b = _mm512_xor_si512( b, c );
			b = _mm512_rol_epi32( b, 7 );
		}

		CCP_TARGET( "avx512f" )
		auto chacha_avx512( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void
		{
			std::uint32_t state[ 16 ];

			state[ 0 ] = 0x61707865;
			state[ 1 ] = 0x3320646e;
			state[ 2 ] = 0x79622d32;
			state[ 3 ] = 0x6b206574;

			for ( unsigned idx = 0; idx < 8; ++idx )
				state[ 4 + idx ] = load_le32( key + idx * 4 );

			state[ 12 ] = counter;
			state[ 13 ] = load_le32( nonce );
			state[ 14 ] = load_le32( nonce + 4 );
			state[ 15 ] = load_le32( nonce + 8 );

			while ( length >= 1024 )
			{
				__m512i v[ 16 ];

				for ( unsigned idx = 0; idx < 16; ++idx )
					v[ idx ] = _mm512_set1_epi32( static_cast< int >( state[ idx ] ) );

				v[ 12 ] = _mm512_add_epi32( _mm512_set1_epi32( static_cast< int >( state[ 12 ] ) ), _mm512_setr_epi32( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ) );

				for ( int round = 0; round < 10; ++round )
				{
					qr_avx512( v[ 0 ], v[ 4 ], v[ 8 ], v[ 12 ] );
					qr_avx512( v[ 1 ], v[ 5 ], v[ 9 ], v[ 13 ] );
					qr_avx512( v[ 2 ], v[ 6 ], v[ 10 ], v[ 14 ] );
					qr_avx512( v[ 3 ], v[ 7 ], v[ 11 ], v[ 15 ] );
					qr_avx512( v[ 0 ], v[ 5 ], v[ 10 ], v[ 15 ] );
					qr_avx512( v[ 1 ], v[ 6 ], v[ 11 ], v[ 12 ] );
					qr_avx512( v[ 2 ], v[ 7 ], v[ 8 ], v[ 13 ] );
					qr_avx512( v[ 3 ], v[ 4 ], v[ 9 ], v[ 14 ] );
				}

				for ( unsigned idx = 0; idx < 16; ++idx )
				{
					if ( idx != 12 )
						v[ idx ] = _mm512_add_epi32( v[ idx ], _mm512_set1_epi32( static_cast< int >( state[ idx ] ) ) );
				}

				v[ 12 ] = _mm512_add_epi32( v[ 12 ], _mm512_add_epi32( _mm512_set1_epi32( static_cast< int >( state[ 12 ] ) ), _mm512_setr_epi32( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ) ) );

				for ( unsigned row = 0; row < 4; ++row )
				{
					const __m512i a = _mm512_unpacklo_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m512i b = _mm512_unpackhi_epi32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const __m512i c = _mm512_unpacklo_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );
					const __m512i d = _mm512_unpackhi_epi32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );

					const __m512i lanes[ 4 ] = {
						_mm512_unpacklo_epi64( a, c ),
						_mm512_unpackhi_epi64( a, c ),
						_mm512_unpacklo_epi64( b, d ),
						_mm512_unpackhi_epi64( b, d ),
					};

					for ( unsigned sub = 0; sub < 4; ++sub )
					{
						const unsigned blk	  = sub;
						const std::size_t off = blk * 64 + row * 16;

						const __m128i ks = _mm512_castsi512_si128( _mm512_shuffle_i32x4( lanes[ sub ], lanes[ sub ], 0 ) );
						const __m128i in = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off ), _mm_xor_si128( in, ks ) );
					}

					for ( unsigned sub = 0; sub < 4; ++sub )
					{
						const unsigned blk	  = 4 + sub;
						const std::size_t off = blk * 64 + row * 16;

						const __m128i ks = _mm512_castsi512_si128( _mm512_shuffle_i32x4( lanes[ sub ], lanes[ sub ], 85 ) );
						const __m128i in = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off ), _mm_xor_si128( in, ks ) );
					}

					for ( unsigned sub = 0; sub < 4; ++sub )
					{
						const unsigned blk	  = 8 + sub;
						const std::size_t off = blk * 64 + row * 16;

						const __m128i ks = _mm512_castsi512_si128( _mm512_shuffle_i32x4( lanes[ sub ], lanes[ sub ], 170 ) );
						const __m128i in = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off ), _mm_xor_si128( in, ks ) );
					}

					for ( unsigned sub = 0; sub < 4; ++sub )
					{
						const unsigned blk	  = 12 + sub;
						const std::size_t off = blk * 64 + row * 16;

						const __m128i ks = _mm512_castsi512_si128( _mm512_shuffle_i32x4( lanes[ sub ], lanes[ sub ], 255 ) );
						const __m128i in = _mm_loadu_si128( reinterpret_cast< const __m128i* >( source + off ) );

						_mm_storeu_si128( reinterpret_cast< __m128i* >( destination + off ), _mm_xor_si128( in, ks ) );
					}
				}

				state[ 12 ] += 16;
				source += 1024;
				destination += 1024;
				length -= 1024;
			}

			if ( length )
				chacha_avx2( destination, source, length, key, nonce, state[ 12 ] );
		}

	#endif

		CCP_TARGET( "avx2" )
		inline auto hsum4_avx2( __m256i v ) noexcept -> std::uint64_t
		{
			const __m256i t = _mm256_add_epi64( v, _mm256_permute4x64_epi64( v, 0x4E ) );
			return static_cast< std::uint64_t >( _mm256_extract_epi64( t, 0 ) ) + static_cast< std::uint64_t >( _mm256_extract_epi64( t, 1 ) );
		}

		CCP_TARGET( "avx2" )
		inline auto poly_accumulate_avx2( const std::uint32_t ( &h )[ 5 ], __m256i ( &d )[ 5 ], const __m256i ( &v_pow )[ 5 ], const __m256i ( &v_pow_x5 )[ 5 ], const std::uint8_t* chunk, bool fold_h ) noexcept -> void
		{
			std::uint32_t m[ 4 ][ 5 ];

			for ( unsigned blk = 0; blk < 4; ++blk )
			{
				const std::uint8_t* p  = chunk + blk * 16;
				const std::uint32_t b0 = load_le32( p );
				const std::uint32_t b1 = load_le32( p + 4 );
				const std::uint32_t b2 = load_le32( p + 8 );
				const std::uint32_t b3 = load_le32( p + 12 );

				m[ blk ][ 0 ] = b0 & limb_mask;
				m[ blk ][ 1 ] = ( ( b0 >> 26 ) | ( b1 << 6 ) ) & limb_mask;
				m[ blk ][ 2 ] = ( ( b1 >> 20 ) | ( b2 << 12 ) ) & limb_mask;
				m[ blk ][ 3 ] = ( ( b2 >> 14 ) | ( b3 << 18 ) ) & limb_mask;
				m[ blk ][ 4 ] = ( b3 >> 8 ) | ( 1u << 24 );
			}

			__m256i v_m[ 5 ];
			for ( unsigned limb = 0; limb < 5; ++limb )
			{
				const __m128i lo = _mm_set_epi32( static_cast< int >( m[ 3 ][ limb ] ), static_cast< int >( m[ 2 ][ limb ] ), static_cast< int >( m[ 1 ][ limb ] ), static_cast< int >( m[ 0 ][ limb ] + ( fold_h ? h[ limb ] : 0 ) ) );
				v_m[ limb ]		 = _mm256_cvtepu32_epi64( lo );
			}

			d[ 0 ] = _mm256_add_epi64( d[ 0 ], _mm256_mul_epu32( v_m[ 0 ], v_pow[ 0 ] ) );
			d[ 0 ] = _mm256_add_epi64( d[ 0 ], _mm256_mul_epu32( v_m[ 1 ], v_pow_x5[ 4 ] ) );
			d[ 0 ] = _mm256_add_epi64( d[ 0 ], _mm256_mul_epu32( v_m[ 2 ], v_pow_x5[ 3 ] ) );
			d[ 0 ] = _mm256_add_epi64( d[ 0 ], _mm256_mul_epu32( v_m[ 3 ], v_pow_x5[ 2 ] ) );
			d[ 0 ] = _mm256_add_epi64( d[ 0 ], _mm256_mul_epu32( v_m[ 4 ], v_pow_x5[ 1 ] ) );

			d[ 1 ] = _mm256_add_epi64( d[ 1 ], _mm256_mul_epu32( v_m[ 0 ], v_pow[ 1 ] ) );
			d[ 1 ] = _mm256_add_epi64( d[ 1 ], _mm256_mul_epu32( v_m[ 1 ], v_pow[ 0 ] ) );
			d[ 1 ] = _mm256_add_epi64( d[ 1 ], _mm256_mul_epu32( v_m[ 2 ], v_pow_x5[ 4 ] ) );
			d[ 1 ] = _mm256_add_epi64( d[ 1 ], _mm256_mul_epu32( v_m[ 3 ], v_pow_x5[ 3 ] ) );
			d[ 1 ] = _mm256_add_epi64( d[ 1 ], _mm256_mul_epu32( v_m[ 4 ], v_pow_x5[ 2 ] ) );

			d[ 2 ] = _mm256_add_epi64( d[ 2 ], _mm256_mul_epu32( v_m[ 0 ], v_pow[ 2 ] ) );
			d[ 2 ] = _mm256_add_epi64( d[ 2 ], _mm256_mul_epu32( v_m[ 1 ], v_pow[ 1 ] ) );
			d[ 2 ] = _mm256_add_epi64( d[ 2 ], _mm256_mul_epu32( v_m[ 2 ], v_pow[ 0 ] ) );
			d[ 2 ] = _mm256_add_epi64( d[ 2 ], _mm256_mul_epu32( v_m[ 3 ], v_pow_x5[ 4 ] ) );
			d[ 2 ] = _mm256_add_epi64( d[ 2 ], _mm256_mul_epu32( v_m[ 4 ], v_pow_x5[ 3 ] ) );

			d[ 3 ] = _mm256_add_epi64( d[ 3 ], _mm256_mul_epu32( v_m[ 0 ], v_pow[ 3 ] ) );
			d[ 3 ] = _mm256_add_epi64( d[ 3 ], _mm256_mul_epu32( v_m[ 1 ], v_pow[ 2 ] ) );
			d[ 3 ] = _mm256_add_epi64( d[ 3 ], _mm256_mul_epu32( v_m[ 2 ], v_pow[ 1 ] ) );
			d[ 3 ] = _mm256_add_epi64( d[ 3 ], _mm256_mul_epu32( v_m[ 3 ], v_pow[ 0 ] ) );
			d[ 3 ] = _mm256_add_epi64( d[ 3 ], _mm256_mul_epu32( v_m[ 4 ], v_pow_x5[ 4 ] ) );

			d[ 4 ] = _mm256_add_epi64( d[ 4 ], _mm256_mul_epu32( v_m[ 0 ], v_pow[ 4 ] ) );
			d[ 4 ] = _mm256_add_epi64( d[ 4 ], _mm256_mul_epu32( v_m[ 1 ], v_pow[ 3 ] ) );
			d[ 4 ] = _mm256_add_epi64( d[ 4 ], _mm256_mul_epu32( v_m[ 2 ], v_pow[ 2 ] ) );
			d[ 4 ] = _mm256_add_epi64( d[ 4 ], _mm256_mul_epu32( v_m[ 3 ], v_pow[ 1 ] ) );
			d[ 4 ] = _mm256_add_epi64( d[ 4 ], _mm256_mul_epu32( v_m[ 4 ], v_pow[ 0 ] ) );
		}

		CCP_TARGET( "avx2" )
		auto poly_blocks_avx2( std::uint32_t ( &h )[ 5 ], const std::uint32_t ( &powers )[ 8 ][ 5 ], const std::uint8_t* message, std::size_t n64 ) noexcept -> void
		{
			__m256i v_pow[ 5 ];
			__m256i v_pow_x5[ 5 ];
			__m256i v_pow_hi[ 5 ];
			__m256i v_pow_hi_x5[ 5 ];

			for ( unsigned limb = 0; limb < 5; ++limb )
			{
				v_pow[ limb ]		= _mm256_set_epi64x( powers[ 0 ][ limb ], powers[ 1 ][ limb ], powers[ 2 ][ limb ], powers[ 3 ][ limb ] );
				v_pow_x5[ limb ]	= _mm256_set_epi64x( powers[ 0 ][ limb ] * 5, powers[ 1 ][ limb ] * 5, powers[ 2 ][ limb ] * 5, powers[ 3 ][ limb ] * 5 );
				v_pow_hi[ limb ]	= _mm256_set_epi64x( powers[ 4 ][ limb ], powers[ 5 ][ limb ], powers[ 6 ][ limb ], powers[ 7 ][ limb ] );
				v_pow_hi_x5[ limb ] = _mm256_set_epi64x( powers[ 4 ][ limb ] * 5, powers[ 5 ][ limb ] * 5, powers[ 6 ][ limb ] * 5, powers[ 7 ][ limb ] * 5 );
			}

			while ( n64 >= 2 )
			{
				__m256i d[ 5 ] = { _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ) };

				poly_accumulate_avx2( h, d, v_pow_hi, v_pow_hi_x5, message, true );
				poly_accumulate_avx2( h, d, v_pow, v_pow_x5, message + 64, false );

				std::uint64_t e0 = hsum4_avx2( d[ 0 ] );
				std::uint64_t e1 = hsum4_avx2( d[ 1 ] );
				std::uint64_t e2 = hsum4_avx2( d[ 2 ] );
				std::uint64_t e3 = hsum4_avx2( d[ 3 ] );
				std::uint64_t e4 = hsum4_avx2( d[ 4 ] );

				std::uint64_t c;
				c = e0 >> 26;

				e0 &= limb_mask;
				e1 += c;
				c = e1 >> 26;

				e1 &= limb_mask;
				e2 += c;
				c = e2 >> 26;

				e2 &= limb_mask;
				e3 += c;
				c = e3 >> 26;

				e3 &= limb_mask;
				e4 += c;
				c = e4 >> 26;

				e4 &= limb_mask;
				e0 += c * 5;
				c = e0 >> 26;

				e0 &= limb_mask;
				e1 += c;

				h[ 0 ] = static_cast< std::uint32_t >( e0 );
				h[ 1 ] = static_cast< std::uint32_t >( e1 );
				h[ 2 ] = static_cast< std::uint32_t >( e2 );
				h[ 3 ] = static_cast< std::uint32_t >( e3 );
				h[ 4 ] = static_cast< std::uint32_t >( e4 );

				message += 128;
				n64 -= 2;
			}

			if ( n64-- )
			{
				__m256i d[ 5 ] = { _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ), _mm256_setzero_si256( ) };

				poly_accumulate_avx2( h, d, v_pow, v_pow_x5, message, true );

				std::uint64_t e0 = hsum4_avx2( d[ 0 ] );
				std::uint64_t e1 = hsum4_avx2( d[ 1 ] );
				std::uint64_t e2 = hsum4_avx2( d[ 2 ] );
				std::uint64_t e3 = hsum4_avx2( d[ 3 ] );
				std::uint64_t e4 = hsum4_avx2( d[ 4 ] );

				std::uint64_t c;
				c = e0 >> 26;

				e0 &= limb_mask;
				e1 += c;
				c = e1 >> 26;

				e1 &= limb_mask;
				e2 += c;
				c = e2 >> 26;

				e2 &= limb_mask;
				e3 += c;
				c = e3 >> 26;

				e3 &= limb_mask;
				e4 += c;
				c = e4 >> 26;

				e4 &= limb_mask;
				e0 += c * 5;
				c = e0 >> 26;

				e0 &= limb_mask;
				e1 += c;

				h[ 0 ] = static_cast< std::uint32_t >( e0 );
				h[ 1 ] = static_cast< std::uint32_t >( e1 );
				h[ 2 ] = static_cast< std::uint32_t >( e2 );
				h[ 3 ] = static_cast< std::uint32_t >( e3 );
				h[ 4 ] = static_cast< std::uint32_t >( e4 );
			}
		}
	}
}

#elif defined( CCP_NEON_ENABLED )

	#if defined( _MSC_VER )
		#include <arm64_neon.h>
	#else
		#include <arm_neon.h>
	#endif

namespace aead
{
	namespace detail
	{
		inline auto rotl16_neon( uint32x4_t v ) noexcept -> uint32x4_t
		{
			return vreinterpretq_u32_u16( vrev32q_u16( vreinterpretq_u16_u32( v ) ) );
		}

		inline auto rotl8_neon( uint32x4_t v ) noexcept -> uint32x4_t
		{
			static const std::uint8_t mask[ 16 ] = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
			return vreinterpretq_u32_u8( vqtbl1q_u8( vreinterpretq_u8_u32( v ), vld1q_u8( mask ) ) );
		}

		inline auto rotl_neon( uint32x4_t v, int n ) noexcept -> uint32x4_t
		{
			return vorrq_u32( vshlq_u32( v, vdupq_n_s32( n ) ), vshlq_u32( v, vdupq_n_s32( n - 32 ) ) );
		}

		inline auto qr_neon( uint32x4_t& a, uint32x4_t& b, uint32x4_t& c, uint32x4_t& d ) noexcept -> void
		{
			a = vaddq_u32( a, b );
			d = veorq_u32( d, a );
			d = rotl16_neon( d );
			c = vaddq_u32( c, d );
			b = veorq_u32( b, c );
			b = rotl_neon( b, 12 );
			a = vaddq_u32( a, b );
			d = veorq_u32( d, a );
			d = rotl8_neon( d );
			c = vaddq_u32( c, d );
			b = veorq_u32( b, c );
			b = rotl_neon( b, 7 );
		}

		auto chacha_neon( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void
		{
			std::uint32_t state[ 16 ];

			state[ 0 ] = 0x61707865;
			state[ 1 ] = 0x3320646e;
			state[ 2 ] = 0x79622d32;
			state[ 3 ] = 0x6b206574;

			for ( unsigned idx = 0; idx < 8; ++idx )
				state[ 4 + idx ] = load_le32( key + idx * 4 );

			state[ 12 ] = counter;
			state[ 13 ] = load_le32( nonce );
			state[ 14 ] = load_le32( nonce + 4 );
			state[ 15 ] = load_le32( nonce + 8 );

			while ( length >= 256 )
			{
				uint32x4_t v[ 16 ];

				for ( unsigned idx = 0; idx < 16; ++idx )
					v[ idx ] = vdupq_n_u32( state[ idx ] );

				v[ 12 ] = vdupq_n_u32( state[ 12 ] );
				v[ 12 ] = vsetq_lane_u32( state[ 12 ] + 1, v[ 12 ], 1 );
				v[ 12 ] = vsetq_lane_u32( state[ 12 ] + 2, v[ 12 ], 2 );
				v[ 12 ] = vsetq_lane_u32( state[ 12 ] + 3, v[ 12 ], 3 );

				for ( int round = 0; round < 10; ++round )
				{
					qr_neon( v[ 0 ], v[ 4 ], v[ 8 ], v[ 12 ] );
					qr_neon( v[ 1 ], v[ 5 ], v[ 9 ], v[ 13 ] );
					qr_neon( v[ 2 ], v[ 6 ], v[ 10 ], v[ 14 ] );
					qr_neon( v[ 3 ], v[ 7 ], v[ 11 ], v[ 15 ] );
					qr_neon( v[ 0 ], v[ 5 ], v[ 10 ], v[ 15 ] );
					qr_neon( v[ 1 ], v[ 6 ], v[ 11 ], v[ 12 ] );
					qr_neon( v[ 2 ], v[ 7 ], v[ 8 ], v[ 13 ] );
					qr_neon( v[ 3 ], v[ 4 ], v[ 9 ], v[ 14 ] );
				}

				for ( unsigned idx = 0; idx < 16; ++idx )
				{
					if ( idx != 12 )
						v[ idx ] = vaddq_u32( v[ idx ], vdupq_n_u32( state[ idx ] ) );
				}

				auto ctr = vdupq_n_u32( state[ 12 ] );
				ctr		 = vsetq_lane_u32( state[ 12 ] + 1, ctr, 1 );
				ctr		 = vsetq_lane_u32( state[ 12 ] + 2, ctr, 2 );
				ctr		 = vsetq_lane_u32( state[ 12 ] + 3, ctr, 3 );
				v[ 12 ]	 = vaddq_u32( v[ 12 ], ctr );

				for ( unsigned row = 0; row < 4; ++row )
				{
					const uint32x4_t a = vzip1q_u32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const uint32x4_t b = vzip2q_u32( v[ row * 4 ], v[ row * 4 + 1 ] );
					const uint32x4_t c = vzip1q_u32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );
					const uint32x4_t d = vzip2q_u32( v[ row * 4 + 2 ], v[ row * 4 + 3 ] );

					const uint32x4_t blocks[ 4 ] = {
						vreinterpretq_u32_u64( vzip1q_u64( vreinterpretq_u64_u32( a ), vreinterpretq_u64_u32( c ) ) ),
						vreinterpretq_u32_u64( vzip2q_u64( vreinterpretq_u64_u32( a ), vreinterpretq_u64_u32( c ) ) ),
						vreinterpretq_u32_u64( vzip1q_u64( vreinterpretq_u64_u32( b ), vreinterpretq_u64_u32( d ) ) ),
						vreinterpretq_u32_u64( vzip2q_u64( vreinterpretq_u64_u32( b ), vreinterpretq_u64_u32( d ) ) ),
					};

					for ( unsigned blk = 0; blk < 4; ++blk )
					{
						const std::size_t off = blk * 64 + row * 16;
						const uint8x16_t in	  = vld1q_u8( source + off );

						vst1q_u8( destination + off, veorq_u8( in, vreinterpretq_u8_u32( blocks[ blk ] ) ) );
					}
				}

				state[ 12 ] += 4;
				source += 256;
				destination += 256;
				length -= 256;
			}

			if ( length )
				chacha_scalar( destination, source, length, key, nonce, state[ 12 ] );
		}
	}
}

#endif
