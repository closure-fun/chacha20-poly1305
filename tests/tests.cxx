#include "chacha20_poly1305.hxx"
#include "chacha20_poly1305_detail.hxx"

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

int failed = 0;
int total  = 0;

auto check( const char* name, bool ok ) -> void
{
	++total;
	std::printf( "%-58s : %s\n", name, ok ? "PASSED" : "FAILED" );
	if ( !ok )
		++failed;
}

auto unhex( std::string_view hex ) -> std::vector< std::uint8_t >
{
	std::vector< std::uint8_t > out;
	char hi	  = 0;
	bool have = false;
	for ( const char c : hex )
	{
		int v = -1;
		if ( c >= '0' && c <= '9' )
			v = c - '0';
		else if ( c >= 'a' && c <= 'f' )
			v = c - 'a' + 10;
		else if ( c >= 'A' && c <= 'F' )
			v = c - 'A' + 10;
		if ( v < 0 )
			continue;
		if ( !have )
		{
			hi	 = static_cast< char >( v );
			have = true;
		}
		else
		{
			out.push_back( static_cast< std::uint8_t >( ( hi << 4 ) | v ) );
			have = false;
		}
	}
	return out;
}

auto eq( const std::uint8_t* a, const std::uint8_t* b, std::size_t length ) -> bool
{
	return std::memcmp( a, b, length ) == 0;
}

auto rng_state = 0x9e3779b97f4a7c15ull;

auto rng( ) -> std::uint64_t
{
	rng_state += 0x9e3779b97f4a7c15ull;
	std::uint64_t z = rng_state;
	z				= ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9ull;
	z				= ( z ^ ( z >> 27 ) ) * 0x94d049bb133111ebull;
	return z ^ ( z >> 31 );
}

auto random_bytes( std::size_t length ) -> std::vector< std::uint8_t >
{
	std::vector< std::uint8_t > out( length );
	for ( auto& byte : out )
		byte = static_cast< std::uint8_t >( rng( ) );
	return out;
}

constexpr std::string_view block_key	  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view block_nonce	  = "000000090000004a00000000";
constexpr std::string_view block_expected = "10f1e7e4d13b5915500fdd1fa32071c4"
											"c7d1f4c733c068030422aa9ac3d46c4e"
											"d2826446079faa0914c2d705d98b02a2"
											"b5129cd1de164eb9cbd083e8a2503c4e";

constexpr std::string_view enc_nonce	= "000000000000004a00000000";
constexpr std::string_view enc_plain	= "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
constexpr std::string_view enc_expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
										  "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
										  "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937"
										  "365af90bbf74a35be6b40b8eedf2785e42874d";

constexpr std::string_view poly_key_252		= "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
constexpr std::string_view poly_message_252 = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570";
constexpr std::string_view poly_tag_252		= "a8061dc1305136c6c22b8baf0c0127a9";

constexpr std::string_view keygen_key	   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
constexpr std::string_view keygen_nonce	   = "000000000001020304050607";
constexpr std::string_view keygen_expected = "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646";

constexpr std::string_view aead_key		  = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
constexpr std::string_view aead_nonce_282 = "070000004041424344454647";
constexpr std::string_view aead_aad_282	  = "50515253c0c1c2c3c4c5c6c7";
constexpr std::string_view aead_ct_282	  = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
											"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
											"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
											"3ff4def08e4b7a9de576d26586cec64b6116";
constexpr std::string_view aead_tag_282	  = "1ae10b594f09e26a7e902ecbd0600691";

constexpr std::string_view aead_key_a5	 = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
constexpr std::string_view aead_nonce_a5 = "000000000102030405060708";
constexpr std::string_view aead_aad_a5	 = "f33388860000000000004e91";
constexpr std::string_view aead_plain_a5 = "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d";
constexpr std::string_view aead_ct_a5	 = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
										   "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
										   "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
										   "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
										   "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
										   "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
										   "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
										   "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
										   "a6ad5cb4022b02709b";
constexpr std::string_view aead_tag_a5	 = "eead9d67890cbb22392336fea1851f38";

struct poly_vector_t
{
	std::string_view key;
	std::string_view message;
	std::string_view tag;
};

constexpr poly_vector_t poly_vectors[] = {
	{ "0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000" },
	{ "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
		"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
		"36e5f6b5c5e06070f0efca96227a863e" },
	{ "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
		"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
		"f3477e7cd95417af89a6b8794c310cf0" },
	{ "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
		"2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
		"4541669a7eaaee61e708dc7cbcc5eb62" },
	{ "0200000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"03000000000000000000000000000000" },
	{ "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
		"02000000000000000000000000000000",
		"03000000000000000000000000000000" },
	{ "0100000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
		"05000000000000000000000000000000" },
	{ "0100000000000000000000000000000000000000000000000000000000000000",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101",
		"00000000000000000000000000000000" },
	{ "0200000000000000000000000000000000000000000000000000000000000000",
		"FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" },
	{ "0100000000000000040000000000000000000000000000000000000000000000",
		"E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000",
		"14000000000000005500000000000000" },
	{ "0100000000000000040000000000000000000000000000000000000000000000",
		"E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000",
		"13000000000000000000000000000000" },
};

auto run_chacha_backends( const std::vector< std::uint8_t >& source, const aead::key_t& key, const aead::nonce_t& nonce, std::uint32_t counter ) -> std::vector< std::vector< std::uint8_t > >
{
	std::vector< std::vector< std::uint8_t > > outs;
	auto run = [ & ]( aead::detail::chacha_fn_t fn, const char* name ) {
		std::vector< std::uint8_t > out( source.size( ) );
		fn( out.data( ), source.data( ), source.size( ), key.bytes.data( ), nonce.bytes.data( ), counter );
		std::printf( "    backend %-10s\n", name );
		outs.push_back( std::move( out ) );
	};

	run( &aead::detail::chacha_scalar, "scalar" );
#if defined( CCP_X86_SIMD )
	run( &aead::detail::chacha_sse2, "sse2" );
	if ( aead::detail::probe_avx2( ) )
		run( &aead::detail::chacha_avx2, "avx2" );
	#if defined( CCP_AVX512_ENABLED )
	if ( aead::detail::probe_avx512f( ) )
		run( &aead::detail::chacha_avx512, "avx512" );
	#endif
#elif defined( CCP_NEON_ENABLED )
	run( &aead::detail::chacha_neon, "neon" );
#endif
	return outs;
}

auto main( ) -> int
{
	std::printf( "chacha20-poly1305 test suite\n\n" );

	const auto key_block   = aead::key_t::from_span( unhex( block_key ) );
	const auto nonce_block = aead::nonce_t::from_span( unhex( block_nonce ) );

	{
		const auto zeros	= std::vector< std::uint8_t >( 64, 0 );
		const auto outs		= run_chacha_backends( zeros, key_block, nonce_block, 1 );
		const auto expected = unhex( block_expected );

		bool all = true;
		for ( const auto& out : outs )
			all = all && eq( out.data( ), expected.data( ), expected.size( ) );

		check( "chacha20 block function rfc 2.3.2 ( all backends )", all );
	}

	{
		const auto plain	= unhex( enc_plain );
		const auto nonce	= aead::nonce_t::from_span( unhex( enc_nonce ) );
		const auto outs		= run_chacha_backends( plain, key_block, nonce, 1 );
		const auto expected = unhex( enc_expected );

		bool all = true;
		for ( const auto& out : outs )
			all = all && eq( out.data( ), expected.data( ), expected.size( ) );

		check( "chacha20 encryption rfc 2.4.2 ( all backends )", all );
	}

	{
		const auto key	 = aead::key_t::from_span( unhex( aead_key ) );
		const auto nonce = aead::nonce_t::from_span( unhex( keygen_nonce ) );

		bool all = true;
		for ( std::size_t length : std::array< std::size_t, 19 > { 0, 1, 17, 63, 64, 65, 127, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1531, 2048, 4097 } )
		{
			const auto source = random_bytes( length );
			const auto outs	  = run_chacha_backends( source, key, nonce, 42 );

			for ( std::size_t idx = 1; idx < outs.size( ); ++idx )
				all = all && eq( outs[ idx ].data( ), outs[ 0 ].data( ), length );
		}

		check( "chacha20 backend equivalengthce ( odd sizes )", all );
	}

	{
		const auto key		= aead::key_t::from_span( unhex( poly_key_252 ) );
		const auto message	= unhex( poly_message_252 );
		const auto tag		= aead::poly1305::mac( message, key );
		const auto expected = unhex( poly_tag_252 );

		check( "poly1305 mac rfc 2.5.2", eq( tag.bytes.data( ), expected.data( ), 16 ) );
		check( "poly1305 verify rfc 2.5.2", aead::poly1305::verify( tag, aead::tag_t::from_span( expected ) ) );
	}

	{
		bool all = true;

		for ( const auto& vec : poly_vectors )
		{
			const auto key		= aead::key_t::from_span( unhex( vec.key ) );
			const auto message	= unhex( vec.message );
			const auto tag		= aead::poly1305::mac( message, key );
			const auto expected = unhex( vec.tag );
			all					= all && eq( tag.bytes.data( ), expected.data( ), 16 );
		}

		check( "poly1305 rfc a.3 vectors ( 1-11 )", all );
	}

	{
		const auto key = aead::key_t::from_span( random_bytes( 32 ) );

		bool all = true;
		for ( std::size_t length : std::array< std::size_t, 13 > { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 1000 } )
		{
			const auto message	 = random_bytes( length );
			const auto reference = aead::poly1305::mac( message, key );

			aead::poly1305::state_t state( key );
			std::size_t offset = 0;

			while ( offset < length )
			{
				const std::size_t chunk = static_cast< std::size_t >( rng( ) % 97 + 1 );
				state.absorb( std::span< const std::uint8_t >( message.data( ) + offset, chunk < length - offset ? chunk : length - offset ) );
				offset += chunk < length - offset ? chunk : length - offset;
			}

			all = all && eq( state.finish( ).bytes.data( ), reference.bytes.data( ), 16 );
		}

		check( "poly1305 streaming vs one shot", all );
	}

	{
		const auto key	 = aead::key_t::from_span( unhex( keygen_key ) );
		const auto nonce = aead::nonce_t::from_span( unhex( keygen_nonce ) );

		std::uint8_t otk[ 64 ] { };
		const auto zeros = std::vector< std::uint8_t >( 64, 0 );

		aead::chacha20::xor_stream( otk, zeros, key, nonce, 0 );
		const auto expected = unhex( keygen_expected );

		check( "poly1305 key gen rfc 2.6.1", eq( otk, expected.data( ), 32 ) );
	}

	{
		const auto key	 = aead::key_t::from_span( unhex( aead_key ) );
		const auto nonce = aead::nonce_t::from_span( unhex( aead_nonce_282 ) );
		const auto aad	 = unhex( aead_aad_282 );
		const auto plain = unhex( enc_plain );

		std::vector< std::uint8_t > cipher( plain.size( ) );
		const auto tag = aead::encrypt( cipher, plain, aad, key, nonce );

		const auto expected_ct	= unhex( aead_ct_282 );
		const auto expected_tag = unhex( aead_tag_282 );

		check( "aead ciphertext rfc 2.8.2", eq( cipher.data( ), expected_ct.data( ), cipher.size( ) ) );
		check( "aead tag rfc 2.8.2", eq( tag.bytes.data( ), expected_tag.data( ), 16 ) );

		std::vector< std::uint8_t > recovered( plain.size( ) );
		check( "aead decrypt rfc 2.8.2", aead::decrypt( recovered, cipher, aad, key, nonce, tag ) && eq( recovered.data( ), plain.data( ), plain.size( ) ) );
	}

	{
		const auto key			= aead::key_t::from_span( unhex( aead_key_a5 ) );
		const auto nonce		= aead::nonce_t::from_span( unhex( aead_nonce_a5 ) );
		const auto aad			= unhex( aead_aad_a5 );
		const auto plain		= unhex( aead_plain_a5 );
		const auto ct_expected	= unhex( aead_ct_a5 );
		const auto tag_expected = unhex( aead_tag_a5 );

		std::vector< std::uint8_t > cipher( plain.size( ) );
		const auto tag = aead::encrypt( cipher, plain, aad, key, nonce );

		check( "aead ciphertext rfc a.5", eq( cipher.data( ), ct_expected.data( ), cipher.size( ) ) );
		check( "aead tag rfc a.5", eq( tag.bytes.data( ), tag_expected.data( ), 16 ) );

		std::vector< std::uint8_t > recovered( plain.size( ) );
		check( "aead decrypt rfc a.5", aead::decrypt( recovered, cipher, aad, key, nonce, tag ) && eq( recovered.data( ), plain.data( ), plain.size( ) ) );
	}

	{
		const auto key	 = aead::key_t::from_span( random_bytes( 32 ) );
		const auto nonce = aead::nonce_t::from_span( random_bytes( 12 ) );
		bool all		 = true;
		for ( std::size_t length : std::array< std::size_t, 16 > { 0, 1, 31, 32, 63, 64, 65, 128, 255, 256, 511, 512, 1023, 1024, 1025, 4096 } )
		{
			const auto plain = random_bytes( length );
			const auto aad	 = random_bytes( static_cast< std::size_t >( rng( ) % 64 ) );

			std::vector< std::uint8_t > cipher( length );
			const auto tag = aead::encrypt( cipher, plain, aad, key, nonce );

			std::vector< std::uint8_t > recovered( length );
			if ( !aead::decrypt( recovered, cipher, aad, key, nonce, tag ) || !eq( recovered.data( ), plain.data( ), length ) )
			{
				all = false;
				break;
			}

			std::vector< std::uint8_t > in_place( plain );
			const auto tag2 = aead::encrypt( in_place, in_place, aad, key, nonce );
			if ( !eq( in_place.data( ), cipher.data( ), length ) || !eq( tag2.bytes.data( ), tag.bytes.data( ), 16 ) )
			{
				all = false;
				break;
			}
			if ( !aead::decrypt( in_place, in_place, aad, key, nonce, tag2 ) || !eq( in_place.data( ), plain.data( ), length ) )
			{
				all = false;
				break;
			}
		}
		check( "aead roundtrip + in place ( odd sizes )", all );
	}

	{
		const auto key	 = aead::key_t::from_span( random_bytes( 32 ) );
		const auto nonce = aead::nonce_t::from_span( random_bytes( 12 ) );
		const auto aad	 = random_bytes( 21 );
		const auto plain = random_bytes( 300 );

		std::vector< std::uint8_t > cipher( plain.size( ) );
		const auto tag = aead::encrypt( cipher, plain, aad, key, nonce );

		std::vector< std::uint8_t > recovered( plain.size( ) );

		auto bad_cipher = cipher;
		bad_cipher[ 200 ] ^= 0x80;
		check( "aead rejects tampered ciphertext", !aead::decrypt( recovered, bad_cipher, aad, key, nonce, tag ) );

		auto bad_aad = aad;
		bad_aad[ 3 ] ^= 1;
		check( "aead rejects tampered aad", !aead::decrypt( recovered, cipher, bad_aad, key, nonce, tag ) );

		auto bad_tag = tag;
		bad_tag.bytes[ 15 ] ^= 1;
		check( "aead rejects tampered tag", !aead::decrypt( recovered, cipher, aad, key, nonce, bad_tag ) );

		const auto other_nonce = aead::nonce_t::from_span( random_bytes( 12 ) );
		check( "aead rejects wrong nonce", !aead::decrypt( recovered, cipher, aad, key, other_nonce, tag ) );

		const auto other_key = aead::key_t::from_span( random_bytes( 32 ) );
		check( "aead rejects wrong key", !aead::decrypt( recovered, cipher, aad, other_key, nonce, tag ) );
	}

	{
		const auto key	 = aead::key_t::from_span( unhex( aead_key ) );
		const auto nonce = aead::nonce_t::from_span( unhex( aead_nonce_282 ) );
		const auto aad	 = unhex( aead_aad_282 );
		const auto plain = unhex( enc_plain );

		const auto sealed = aead::encrypt( plain, aad, key, nonce );
		bool all		  = sealed.has_value( ) && sealed->size( ) == plain.size( ) + 16;
		if ( all )
		{
			all = eq( sealed->data( ), unhex( aead_ct_282 ).data( ), plain.size( ) ) && eq( sealed->data( ) + plain.size( ), unhex( aead_tag_282 ).data( ), 16 );

			const auto opened = aead::decrypt( *sealed, aad, key, nonce );
			all				  = all && opened.has_value( ) && eq( opened->data( ), plain.data( ), plain.size( ) );
		}

		auto corrupt = *sealed;
		corrupt[ 7 ] ^= 4;
		all = all && !aead::decrypt( corrupt, aad, key, nonce ).has_value( );
		check( "aead expected/vector convenience api", all );
	}

	std::printf( "\n%d/%d checks passed\n", total - failed, total );
	return failed == 0 ? 0 : 1;
}
