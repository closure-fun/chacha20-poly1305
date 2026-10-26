#ifndef CHACHA20_POLY1305_HXX
#define CHACHA20_POLY1305_HXX

#include "detail.hxx"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <version>

#if __cplusplus >= 202302L || ( defined( _MSVC_LANG ) && _MSVC_LANG >= 202302L )
	#define CCP_HAS_EXPECTED 1
	#include <expected>
#else
	#include <optional>
#endif
#include <span>
#include <vector>

namespace aead
{
	static_assert( std::endian::native == std::endian::little, "chacha20-poly1305 requires a little endian system" );

	struct key_t
	{
		std::array< std::uint8_t, 32 > bytes { };

		[[nodiscard]] constexpr static auto from_span( std::span< const std::uint8_t > source ) -> key_t
		{
			key_t out { };

			for ( std::size_t idx = 0; idx < 32; ++idx )
				out.bytes[ idx ] = source[ idx ];

			return out;
		}
	};

	struct nonce_t
	{
		std::array< std::uint8_t, 12 > bytes { };

		[[nodiscard]] constexpr static auto from_span( std::span< const std::uint8_t > source ) -> nonce_t
		{
			nonce_t out { };

			for ( std::size_t idx = 0; idx < 12; ++idx )
				out.bytes[ idx ] = source[ idx ];

			return out;
		}
	};

	struct tag_t
	{
		std::array< std::uint8_t, 16 > bytes { };

		[[nodiscard]] constexpr static auto from_span( std::span< const std::uint8_t > source ) -> tag_t
		{
			tag_t out { };

			for ( std::size_t idx = 0; idx < 16; ++idx )
				out.bytes[ idx ] = source[ idx ];

			return out;
		}
	};

	namespace chacha20
	{
		auto xor_stream( std::span< std::uint8_t > destination, std::span< const std::uint8_t > source, const key_t& key, const nonce_t& nonce, std::uint32_t counter = 0 ) noexcept -> void;
	}

	namespace poly1305
	{
		class state_t
		{
		public:
			explicit state_t( const key_t& one_time_key ) noexcept;
			~state_t( ) noexcept;

			state_t( const state_t& )		 = delete;
			auto operator=( const state_t& ) = delete;

			state_t( state_t&& other ) noexcept;
			auto operator=( state_t&& other ) noexcept -> state_t&;

			auto absorb( std::span< const std::uint8_t > message ) noexcept -> void;
			[[nodiscard]] auto finish( ) noexcept -> tag_t;

		private:
			detail::poly_state_t state;
		};

		[[nodiscard]] auto mac( std::span< const std::uint8_t > message, const key_t& one_time_key ) noexcept -> tag_t;
		[[nodiscard]] auto verify( const tag_t& a, const tag_t& b ) noexcept -> bool;
	}

	enum class error_t
	{
		auth_failed,
		invalid_size,
	};

	[[nodiscard]] auto encrypt( std::span< std::uint8_t > cipher, std::span< const std::uint8_t > plain, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) noexcept -> tag_t;
	[[nodiscard]] auto decrypt( std::span< std::uint8_t > plain_out, std::span< const std::uint8_t > cipher, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce, const tag_t& tag ) noexcept -> bool;

#if defined( CCP_HAS_EXPECTED )
	[[nodiscard]] inline auto encrypt( std::span< const std::uint8_t > plain, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::expected< std::vector< std::uint8_t >, error_t >
	{
		if ( plain.size( ) / 64 + 1 > 0xfffffffeu )
			return std::unexpected( error_t::invalid_size );
		std::vector< std::uint8_t > out( plain.size( ) + 16 );
		const auto tag = encrypt( std::span< std::uint8_t >( out ).first( plain.size( ) ), plain, aad, key, nonce );
		std::memcpy( out.data( ) + plain.size( ), tag.bytes.data( ), 16 );
		return out;
	}
	[[nodiscard]] inline auto decrypt( std::span< const std::uint8_t > cipher_and_tag, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::expected< std::vector< std::uint8_t >, error_t >
	{
		if ( cipher_and_tag.size( ) < 16 )
			return std::unexpected( error_t::invalid_size );
		const auto cipher_len = cipher_and_tag.size( ) - 16;
		if ( cipher_len / 64 + 1 > 0xfffffffeu )
			return std::unexpected( error_t::invalid_size );
		std::vector< std::uint8_t > out( cipher_len );
		if ( !decrypt( out, cipher_and_tag.first( cipher_len ), aad, key, nonce, tag_t::from_span( cipher_and_tag.subspan( cipher_len ) ) ) )
			return std::unexpected( error_t::auth_failed );
		return out;
	}
#else
	[[nodiscard]] inline auto encrypt( std::span< const std::uint8_t > plain, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::optional< std::vector< std::uint8_t > >
	{
		if ( plain.size( ) / 64 + 1 > 0xfffffffeu )
			return std::nullopt;
		std::vector< std::uint8_t > out( plain.size( ) + 16 );
		const auto tag = encrypt( std::span< std::uint8_t >( out ).first( plain.size( ) ), plain, aad, key, nonce );
		std::memcpy( out.data( ) + plain.size( ), tag.bytes.data( ), 16 );
		return out;
	}
	[[nodiscard]] inline auto decrypt( std::span< const std::uint8_t > cipher_and_tag, std::span< const std::uint8_t > aad, const key_t& key, const nonce_t& nonce ) -> std::optional< std::vector< std::uint8_t > >
	{
		if ( cipher_and_tag.size( ) < 16 )
			return std::nullopt;
		const auto cipher_len = cipher_and_tag.size( ) - 16;
		if ( cipher_len / 64 + 1 > 0xfffffffeu )
			return std::nullopt;
		std::vector< std::uint8_t > out( cipher_len );
		if ( !decrypt( out, cipher_and_tag.first( cipher_len ), aad, key, nonce, tag_t::from_span( cipher_and_tag.subspan( cipher_len ) ) ) )
			return std::nullopt;
		return out;
	}
#endif
}

#endif
