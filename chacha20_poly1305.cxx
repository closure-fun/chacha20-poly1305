#include "chacha20_poly1305.hxx"

#include <cstring>
#include <new>

namespace aead
{
	namespace detail
	{
		auto secure_zero( void* pointer, std::size_t length ) noexcept -> void
		{
			auto* bytes = static_cast< volatile std::uint8_t* >( pointer );
			while ( length >= 8 )
			{
				*reinterpret_cast< volatile std::uint64_t* >( bytes ) = 0;
				bytes += 8;
				length -= 8;
			}

			while ( length-- )
				*bytes++ = 0;
		}

		constexpr auto rotl( std::uint32_t v, unsigned n ) noexcept -> std::uint32_t
		{
			return ( v << n ) | ( v >> ( 32 - n ) );
		}

		inline auto quarter_round( std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d ) noexcept -> void
		{
			a += b;
			d ^= a;
			d = rotl( d, 16 );

			c += d;
			b ^= c;
			b = rotl( b, 12 );

			a += b;
			d ^= a;
			d = rotl( d, 8 );

			c += d;
			b ^= c;
			b = rotl( b, 7 );
		}

		auto chacha_scalar( std::uint8_t* destination, const std::uint8_t* source, std::size_t length, const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter ) noexcept -> void
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

			while ( length >= 64 )
			{
				std::uint32_t x0 = state[ 0 ], x1 = state[ 1 ], x2 = state[ 2 ], x3 = state[ 3 ], x4 = state[ 4 ], x5 = state[ 5 ], x6 = state[ 6 ], x7 = state[ 7 ];
				std::uint32_t x8 = state[ 8 ], x9 = state[ 9 ], x10 = state[ 10 ], x11 = state[ 11 ], x12 = state[ 12 ], x13 = state[ 13 ], x14 = state[ 14 ], x15 = state[ 15 ];

				for ( int round = 0; round < 10; ++round )
				{
					quarter_round( x0, x4, x8, x12 );
					quarter_round( x1, x5, x9, x13 );
					quarter_round( x2, x6, x10, x14 );
					quarter_round( x3, x7, x11, x15 );
					quarter_round( x0, x5, x10, x15 );
					quarter_round( x1, x6, x11, x12 );
					quarter_round( x2, x7, x8, x13 );
					quarter_round( x3, x4, x9, x14 );
				}

				alignas( 16 ) std::uint32_t keystream[ 16 ];
				keystream[ 0 ]	= x0 + state[ 0 ];
				keystream[ 1 ]	= x1 + state[ 1 ];
				keystream[ 2 ]	= x2 + state[ 2 ];
				keystream[ 3 ]	= x3 + state[ 3 ];
				keystream[ 4 ]	= x4 + state[ 4 ];
				keystream[ 5 ]	= x5 + state[ 5 ];
				keystream[ 6 ]	= x6 + state[ 6 ];
				keystream[ 7 ]	= x7 + state[ 7 ];
				keystream[ 8 ]	= x8 + state[ 8 ];
				keystream[ 9 ]	= x9 + state[ 9 ];
				keystream[ 10 ] = x10 + state[ 10 ];
				keystream[ 11 ] = x11 + state[ 11 ];
				keystream[ 12 ] = x12 + state[ 12 ];
				keystream[ 13 ] = x13 + state[ 13 ];
				keystream[ 14 ] = x14 + state[ 14 ];
				keystream[ 15 ] = x15 + state[ 15 ];

				for ( unsigned word = 0; word < 8; ++word )
				{
					const auto block = ( static_cast< std::uint64_t >( keystream[ 2 * word ] ) | ( static_cast< std::uint64_t >( keystream[ 2 * word + 1 ] ) << 32 ) ) ^ load_le64( source + word * 8 );
					store_le64( destination + word * 8, block );
				}

				++state[ 12 ];
				source += 64;
				destination += 64;
				length -= 64;
			}

			if ( length )
			{
				std::uint32_t x0 = state[ 0 ], x1 = state[ 1 ], x2 = state[ 2 ], x3 = state[ 3 ], x4 = state[ 4 ], x5 = state[ 5 ], x6 = state[ 6 ], x7 = state[ 7 ];
				std::uint32_t x8 = state[ 8 ], x9 = state[ 9 ], x10 = state[ 10 ], x11 = state[ 11 ], x12 = state[ 12 ], x13 = state[ 13 ], x14 = state[ 14 ], x15 = state[ 15 ];

				for ( int round = 0; round < 10; ++round )
				{
					quarter_round( x0, x4, x8, x12 );
					quarter_round( x1, x5, x9, x13 );
					quarter_round( x2, x6, x10, x14 );
					quarter_round( x3, x7, x11, x15 );
					quarter_round( x0, x5, x10, x15 );
					quarter_round( x1, x6, x11, x12 );
					quarter_round( x2, x7, x8, x13 );
					quarter_round( x3, x4, x9, x14 );
				}

				alignas( 16 ) std::uint32_t keystream[ 16 ];
				keystream[ 0 ]	= x0 + state[ 0 ];
				keystream[ 1 ]	= x1 + state[ 1 ];
				keystream[ 2 ]	= x2 + state[ 2 ];
				keystream[ 3 ]	= x3 + state[ 3 ];
				keystream[ 4 ]	= x4 + state[ 4 ];
				keystream[ 5 ]	= x5 + state[ 5 ];
				keystream[ 6 ]	= x6 + state[ 6 ];
				keystream[ 7 ]	= x7 + state[ 7 ];
				keystream[ 8 ]	= x8 + state[ 8 ];
				keystream[ 9 ]	= x9 + state[ 9 ];
				keystream[ 10 ] = x10 + state[ 10 ];
				keystream[ 11 ] = x11 + state[ 11 ];
				keystream[ 12 ] = x12 + state[ 12 ];
				keystream[ 13 ] = x13 + state[ 13 ];
				keystream[ 14 ] = x14 + state[ 14 ];
				keystream[ 15 ] = x15 + state[ 15 ];

				for ( std::size_t idx = 0; idx < length; ++idx )
					destination[ idx ] = source[ idx ] ^ static_cast< std::uint8_t >( keystream[ idx >> 2 ] >> ( ( idx & 3 ) * 8 ) );
			}
		}

		constexpr std::uint32_t limb_mask = 0x03ffffff;

		auto poly_mul_reduce( std::uint32_t ( &out )[ 5 ], const std::uint32_t ( &a )[ 5 ], const std::uint32_t ( &b )[ 5 ] ) noexcept -> void
		{
			const std::uint32_t s1 = b[ 1 ] * 5, s2 = b[ 2 ] * 5, s3 = b[ 3 ] * 5, s4 = b[ 4 ] * 5;

			std::uint64_t d0 = static_cast< std::uint64_t >( a[ 0 ] ) * b[ 0 ] + static_cast< std::uint64_t >( a[ 1 ] ) * s4 + static_cast< std::uint64_t >( a[ 2 ] ) * s3 + static_cast< std::uint64_t >( a[ 3 ] ) * s2 + static_cast< std::uint64_t >( a[ 4 ] ) * s1;
			std::uint64_t d1 = static_cast< std::uint64_t >( a[ 0 ] ) * b[ 1 ] + static_cast< std::uint64_t >( a[ 1 ] ) * b[ 0 ] + static_cast< std::uint64_t >( a[ 2 ] ) * s4 + static_cast< std::uint64_t >( a[ 3 ] ) * s3 + static_cast< std::uint64_t >( a[ 4 ] ) * s2;
			std::uint64_t d2 = static_cast< std::uint64_t >( a[ 0 ] ) * b[ 2 ] + static_cast< std::uint64_t >( a[ 1 ] ) * b[ 1 ] + static_cast< std::uint64_t >( a[ 2 ] ) * b[ 0 ] + static_cast< std::uint64_t >( a[ 3 ] ) * s4 + static_cast< std::uint64_t >( a[ 4 ] ) * s3;
			std::uint64_t d3 = static_cast< std::uint64_t >( a[ 0 ] ) * b[ 3 ] + static_cast< std::uint64_t >( a[ 1 ] ) * b[ 2 ] + static_cast< std::uint64_t >( a[ 2 ] ) * b[ 1 ] + static_cast< std::uint64_t >( a[ 3 ] ) * b[ 0 ] + static_cast< std::uint64_t >( a[ 4 ] ) * s4;
			std::uint64_t d4 = static_cast< std::uint64_t >( a[ 0 ] ) * b[ 4 ] + static_cast< std::uint64_t >( a[ 1 ] ) * b[ 3 ] + static_cast< std::uint64_t >( a[ 2 ] ) * b[ 2 ] + static_cast< std::uint64_t >( a[ 3 ] ) * b[ 1 ] + static_cast< std::uint64_t >( a[ 4 ] ) * b[ 0 ];

			std::uint64_t c;
			c		 = d0 >> 26;
			out[ 0 ] = static_cast< std::uint32_t >( d0 ) & limb_mask;

			d1 += c;
			c		 = d1 >> 26;
			out[ 1 ] = static_cast< std::uint32_t >( d1 ) & limb_mask;

			d2 += c;
			c		 = d2 >> 26;
			out[ 2 ] = static_cast< std::uint32_t >( d2 ) & limb_mask;

			d3 += c;
			c		 = d3 >> 26;
			out[ 3 ] = static_cast< std::uint32_t >( d3 ) & limb_mask;
			d4 += c;

			c		 = d4 >> 26;
			out[ 4 ] = static_cast< std::uint32_t >( d4 ) & limb_mask;
			out[ 0 ] += static_cast< std::uint32_t >( c ) * 5;

			c = out[ 0 ] >> 26;
			out[ 0 ] &= limb_mask;
			out[ 1 ] += static_cast< std::uint32_t >( c );
		}

		auto poly_absorb_block( std::uint32_t ( &h )[ 5 ], const std::uint32_t ( &r )[ 5 ], const std::uint8_t* block, std::size_t length ) noexcept -> void
		{
			std::uint8_t padded[ 17 ] { };
			std::memcpy( padded, block, length );

			padded[ length ] = 0x01;

			const std::uint32_t b0 = load_le32( padded );
			const std::uint32_t b1 = load_le32( padded + 4 );
			const std::uint32_t b2 = load_le32( padded + 8 );
			const std::uint32_t b3 = load_le32( padded + 12 );
			const std::uint32_t b4 = padded[ 16 ];

			std::uint32_t sum[ 5 ];

			sum[ 0 ] = h[ 0 ] + ( b0 & limb_mask );
			sum[ 1 ] = h[ 1 ] + ( ( ( b0 >> 26 ) | ( b1 << 6 ) ) & limb_mask );
			sum[ 2 ] = h[ 2 ] + ( ( ( b1 >> 20 ) | ( b2 << 12 ) ) & limb_mask );
			sum[ 3 ] = h[ 3 ] + ( ( ( b2 >> 14 ) | ( b3 << 18 ) ) & limb_mask );
			sum[ 4 ] = h[ 4 ] + ( ( b3 >> 8 ) | ( b4 << 24 ) );

			poly_mul_reduce( h, sum, r );
		}

		auto poly_finalize( std::uint32_t ( &h )[ 5 ], const std::uint32_t ( &s )[ 4 ], std::uint8_t* tag ) noexcept -> void
		{
			std::uint32_t c;
			std::uint32_t h0 = h[ 0 ], h1 = h[ 1 ], h2 = h[ 2 ], h3 = h[ 3 ], h4 = h[ 4 ];

			c = h1 >> 26;
			h1 &= limb_mask;
			h2 += c;

			c = h2 >> 26;
			h2 &= limb_mask;
			h3 += c;

			c = h3 >> 26;
			h3 &= limb_mask;
			h4 += c;

			c = h4 >> 26;
			h4 &= limb_mask;
			h0 += c * 5;

			c = h0 >> 26;
			h0 &= limb_mask;
			h1 += c;

			std::uint32_t g0 = h0 + 5;
			c				 = g0 >> 26;
			g0 &= limb_mask;

			std::uint32_t g1 = h1 + c;
			c				 = g1 >> 26;
			g1 &= limb_mask;

			std::uint32_t g2 = h2 + c;
			c				 = g2 >> 26;
			g2 &= limb_mask;

			std::uint32_t g3 = h3 + c;
			c				 = g3 >> 26;
			g3 &= limb_mask;
			std::uint32_t g4 = h4 + c - ( 1u << 26 );

			std::uint32_t mask = ( g4 >> 31 ) - 1;

			g0 &= mask;
			g1 &= mask;
			g2 &= mask;
			g3 &= mask;
			g4 &= mask;

			mask = ~mask;

			h0 = ( h0 & mask ) | g0;
			h1 = ( h1 & mask ) | g1;
			h2 = ( h2 & mask ) | g2;
			h3 = ( h3 & mask ) | g3;
			h4 = ( h4 & mask ) | g4;

			std::uint64_t f;
			std::uint32_t w0 = static_cast< std::uint32_t >( static_cast< std::uint64_t >( h0 ) | ( static_cast< std::uint64_t >( h1 ) << 26 ) );
			std::uint32_t w1 = static_cast< std::uint32_t >( ( static_cast< std::uint64_t >( h1 ) >> 6 ) | ( static_cast< std::uint64_t >( h2 ) << 20 ) );
			std::uint32_t w2 = static_cast< std::uint32_t >( ( static_cast< std::uint64_t >( h2 ) >> 12 ) | ( static_cast< std::uint64_t >( h3 ) << 14 ) );
			std::uint32_t w3 = static_cast< std::uint32_t >( ( static_cast< std::uint64_t >( h3 ) >> 18 ) | ( static_cast< std::uint64_t >( h4 ) << 8 ) );

			f  = static_cast< std::uint64_t >( w0 ) + s[ 0 ];
			w0 = static_cast< std::uint32_t >( f );

			f  = static_cast< std::uint64_t >( w1 ) + s[ 1 ] + ( f >> 32 );
			w1 = static_cast< std::uint32_t >( f );

			f  = static_cast< std::uint64_t >( w2 ) + s[ 2 ] + ( f >> 32 );
			w2 = static_cast< std::uint32_t >( f );

			f  = static_cast< std::uint64_t >( w3 ) + s[ 3 ] + ( f >> 32 );
			w3 = static_cast< std::uint32_t >( f );

			store_le32( tag, w0 );
			store_le32( tag + 4, w1 );
			store_le32( tag + 8, w2 );
			store_le32( tag + 12, w3 );
		}

		auto poly_blocks_scalar( std::uint32_t ( &h )[ 5 ], const std::uint32_t ( &r )[ 5 ], const std::uint8_t* message, std::size_t n64 ) noexcept -> void
		{
			for ( std::size_t chunk = 0; chunk < n64; ++chunk )
				for ( unsigned block = 0; block < 4; ++block )
					poly_absorb_block( h, r, message + chunk * 64 + block * 16, 16 );
		}

		auto poly_init_state( poly_state_t& st, const std::uint8_t* key ) noexcept -> void
		{
			const std::uint32_t t0 = load_le32( key ) & 0x0fffffff;
			const std::uint32_t t1 = load_le32( key + 4 ) & 0x0ffffffc;
			const std::uint32_t t2 = load_le32( key + 8 ) & 0x0ffffffc;
			const std::uint32_t t3 = load_le32( key + 12 ) & 0x0ffffffc;

			st.h[ 0 ] = st.h[ 1 ] = st.h[ 2 ] = st.h[ 3 ] = st.h[ 4 ] = 0;
			st.r[ 0 ]												  = t0 & limb_mask;
			st.r[ 1 ]												  = ( ( t0 >> 26 ) | ( t1 << 6 ) ) & limb_mask;
			st.r[ 2 ]												  = ( ( t1 >> 20 ) | ( t2 << 12 ) ) & limb_mask;
			st.r[ 3 ]												  = ( ( t2 >> 14 ) | ( t3 << 18 ) ) & limb_mask;
			st.r[ 4 ]												  = t3 >> 8;
			st.s[ 0 ]												  = load_le32( key + 16 );
			st.s[ 1 ]												  = load_le32( key + 20 );
			st.s[ 2 ]												  = load_le32( key + 24 );
			st.s[ 3 ]												  = load_le32( key + 28 );
			st.buffered												  = 0;

#if defined( CCP_X86_SIMD )
			st.use_avx2 = []( ) noexcept {
				static const bool has = probe_avx2( );
				return has;
			}( );
#else
			st.use_avx2 = false;
#endif
			st.powers_ready = false;
		}

		auto poly_mac_small( const std::uint8_t* key, const std::uint8_t* message, std::size_t length, std::uint8_t* tag ) noexcept -> void
		{
			const std::uint32_t t0 = load_le32( key ) & 0x0fffffff;
			const std::uint32_t t1 = load_le32( key + 4 ) & 0x0ffffffc;
			const std::uint32_t t2 = load_le32( key + 8 ) & 0x0ffffffc;
			const std::uint32_t t3 = load_le32( key + 12 ) & 0x0ffffffc;

			std::uint32_t r[ 5 ];
			r[ 0 ] = t0 & limb_mask;
			r[ 1 ] = ( ( t0 >> 26 ) | ( t1 << 6 ) ) & limb_mask;
			r[ 2 ] = ( ( t1 >> 20 ) | ( t2 << 12 ) ) & limb_mask;
			r[ 3 ] = ( ( t2 >> 14 ) | ( t3 << 18 ) ) & limb_mask;
			r[ 4 ] = t3 >> 8;

			std::uint32_t h[ 5 ] { };

			while ( length >= 16 )
			{
				poly_absorb_block( h, r, message, 16 );
				message += 16;
				length -= 16;
			}

			if ( length )
				poly_absorb_block( h, r, message, length );

			std::uint32_t s[ 4 ] = { load_le32( key + 16 ), load_le32( key + 20 ), load_le32( key + 24 ), load_le32( key + 28 ) };
			poly_finalize( h, s, tag );

			secure_zero( r, sizeof( r ) );
			secure_zero( s, sizeof( s ) );
		}

		auto poly_blocks( poly_state_t& st, const std::uint8_t* message, std::size_t n64 ) noexcept -> void
		{
#if defined( CCP_X86_SIMD )
			if ( st.use_avx2 && n64 >= 3 )
			{
				if ( !st.powers_ready )
				{
					for ( unsigned limb = 0; limb < 5; ++limb )
						st.powers[ 0 ][ limb ] = st.r[ limb ];

					for ( unsigned idx = 1; idx < 8; ++idx )
						poly_mul_reduce( st.powers[ idx ], st.powers[ idx - 1 ], st.r );

					st.powers_ready = true;
				}

				poly_blocks_avx2( st.h, st.powers, message, n64 );
				return;
			}
#endif
			poly_blocks_scalar( st.h, st.r, message, n64 );
		}

		auto poly_absorb( poly_state_t& st, const std::uint8_t* data, std::size_t length ) noexcept -> void
		{
			if ( st.buffered )
			{
				const std::size_t take = length < 64 - st.buffered ? length : 64 - st.buffered;
				std::memcpy( st.buffer + st.buffered, data, take );
				st.buffered += take;
				data += take;
				length -= take;

				if ( st.buffered == 64 )
				{
					poly_blocks( st, st.buffer, 1 );
					st.buffered = 0;
				}
			}

			const std::size_t n64 = length / 64;
			if ( n64 )
			{
				poly_blocks( st, data, n64 );
				data += n64 * 64;
				length -= n64 * 64;
			}

			if ( length )
			{
				std::memcpy( st.buffer, data, length );
				st.buffered = length;
			}
		}

		auto poly_finish( poly_state_t& st, std::uint8_t* tag ) noexcept -> void
		{
			const std::uint8_t* pending = st.buffer;
			std::size_t remaining		= st.buffered;

			while ( remaining >= 16 )
			{
				poly_absorb_block( st.h, st.r, pending, 16 );

				pending += 16;
				remaining -= 16;
			}

			if ( remaining )
				poly_absorb_block( st.h, st.r, pending, remaining );

			poly_finalize( st.h, st.s, tag );
			secure_zero( st.buffer, sizeof( st.buffer ) );
		}

		auto resolve_chacha( ) noexcept -> chacha_fn_t
		{
			static const chacha_fn_t fn = []( ) noexcept -> chacha_fn_t {
#if defined( CCP_X86_SIMD )
	#if defined( CCP_AVX512_ENABLED )
				if ( probe_avx512f( ) )
					return &chacha_avx512;
	#endif
				if ( probe_avx2( ) )
					return &chacha_avx2;
				return &chacha_sse2;
#elif defined( CCP_NEON_ENABLED )
				return &chacha_neon;
#else
				return &chacha_scalar;
#endif
			}( );
			return fn;
		}
	}

	namespace chacha20
	{
		auto xor_stream( std::span< std::uint8_t > destination, std::span< const std::uint8_t > source, const key_t& key, const nonce_t& nonce, std::uint32_t counter ) noexcept -> void
		{
			detail::resolve_chacha( )( destination.data( ), source.data( ), source.size( ), key.bytes.data( ), nonce.bytes.data( ), counter );
		}
	}

	namespace poly1305
	{
		state_t::state_t( const key_t& one_time_key ) noexcept
		{
			detail::poly_init_state( state, one_time_key.bytes.data( ) );
		}

		state_t::~state_t( ) noexcept
		{
			detail::secure_zero( &state, sizeof( state ) );
		}

		state_t::state_t( state_t&& other ) noexcept
			: state( other.state )
		{
			detail::secure_zero( &other.state, sizeof( other.state ) );
			other.state.buffered = 0;
		}

		auto state_t::operator=( state_t&& other ) noexcept -> state_t&
		{
			if ( this != &other )
			{
				state = other.state;
				detail::secure_zero( &other.state, sizeof( other.state ) );
				other.state.buffered = 0;
			}

			return *this;
		}

		auto state_t::absorb( std::span< const std::uint8_t > message ) noexcept -> void
		{
			detail::poly_absorb( state, message.data( ), message.size( ) );
		}

		auto state_t::finish( ) noexcept -> tag_t
		{
			tag_t out;
			detail::poly_finish( state, out.bytes.data( ) );
			return out;
		}

		auto mac( std::span< const std::uint8_t > message, const key_t& one_time_key ) noexcept -> tag_t
		{
			tag_t out;

			if ( message.size( ) < 256 )
				detail::poly_mac_small( one_time_key.bytes.data( ), message.data( ), message.size( ), out.bytes.data( ) );
			else
			{
				state_t state( one_time_key );
				state.absorb( message );
				out = state.finish( );
			}

			return out;
		}

		auto verify( const tag_t& a, const tag_t& b ) noexcept -> bool
		{
			std::uint8_t diff = 0;

			for ( std::size_t idx = 0; idx < 16; ++idx )
				diff |= a.bytes[ idx ] ^ b.bytes[ idx ];

			return diff == 0;
		}
	}

	namespace
	{
		alignas( 64 ) constexpr std::uint8_t zeros[ 64 ] { };
		constexpr std::uint8_t pad[ 16 ] { };

		auto mac_aead_input( const std::uint8_t* otk, std::span< const std::uint8_t > aad, std::span< const std::uint8_t > data, std::size_t data_length ) noexcept -> tag_t
		{
			poly1305::state_t state( key_t::from_span( std::span< const std::uint8_t >( otk, 32 ) ) );

			state.absorb( aad );
			state.absorb( std::span< const std::uint8_t >( pad ).first( detail::pad16( aad.size( ) ) ) );
			state.absorb( std::span< const std::uint8_t >( data ).first( data_length ) );
			state.absorb( std::span< const std::uint8_t >( pad ).first( detail::pad16( data_length ) ) );

			std::uint8_t lengthgths[ 16 ];
			detail::store_le64( lengthgths, aad.size( ) );
			detail::store_le64( lengthgths + 8, data_length );

			state.absorb( lengthgths );

			return state.finish( );
		}
	}

	auto encrypt( std::span< std::uint8_t > cipher, std::span< const std::uint8_t > plain, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) noexcept -> tag_t
	{
		const auto stream = detail::resolve_chacha( );

		alignas( 64 ) std::uint8_t otk_block[ 64 ];

		stream( otk_block, zeros, 64, key.bytes.data( ), nonce.bytes.data( ), 0 );
		stream( cipher.data( ), plain.data( ), plain.size( ), key.bytes.data( ), nonce.bytes.data( ), 1 );

		auto tag = mac_aead_input( otk_block, aad, cipher, plain.size( ) );
		detail::secure_zero( otk_block, sizeof( otk_block ) );

		return tag;
	}

	auto decrypt( std::span< std::uint8_t > plain_out, std::span< const std::uint8_t > cipher, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce, const tag_t& tag ) noexcept -> bool
	{
		const auto stream = detail::resolve_chacha( );

		alignas( 64 ) std::uint8_t otk_block[ 64 ];

		stream( otk_block, zeros, 64, key.bytes.data( ), nonce.bytes.data( ), 0 );

		const auto computed = mac_aead_input( otk_block, aad, cipher, cipher.size( ) );
		detail::secure_zero( otk_block, sizeof( otk_block ) );

		if ( !poly1305::verify( computed, tag ) )
			return false;

		stream( plain_out.data( ), cipher.data( ), cipher.size( ), key.bytes.data( ), nonce.bytes.data( ), 1 );
		return true;
	}

	auto encrypt( std::span< const std::uint8_t > plain, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::expected< std::vector< std::uint8_t >, error_t >
	{
		if ( plain.size( ) / 64 + 1 > 0xfffffffeu )
			return std::unexpected( error_t::invalid_size );

		try
		{
			std::vector< std::uint8_t > out( plain.size( ) + 16 );

			const auto tag = encrypt( std::span< std::uint8_t >( out ).first( plain.size( ) ), plain, aad, key, nonce );
			std::memcpy( out.data( ) + plain.size( ), tag.bytes.data( ), 16 );

			return out;
		}
		catch ( const std::bad_alloc& )
		{
			return std::unexpected( error_t::invalid_size );
		}
	}

	auto decrypt( std::span< const std::uint8_t > cipher_and_tag, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::expected< std::vector< std::uint8_t >, error_t >
	{
		if ( cipher_and_tag.size( ) < 16 )
			return std::unexpected( error_t::invalid_size );

		const auto lengthgth = cipher_and_tag.size( ) - 16;
		if ( lengthgth / 64 + 1 > 0xfffffffeu )
			return std::unexpected( error_t::invalid_size );

		try
		{
			std::vector< std::uint8_t > out( lengthgth );

			if ( !decrypt( out, cipher_and_tag.first( lengthgth ), aad, key, nonce, tag_t::from_span( cipher_and_tag.subspan( lengthgth ) ) ) )
				return std::unexpected( error_t::auth_failed );

			return out;
		}
		catch ( const std::bad_alloc& )
		{
			return std::unexpected( error_t::invalid_size );
		}
	}
}
