#ifndef DIGESTIVE_DIGEST_HPP
#define DIGESTIVE_DIGEST_HPP

#include "endian.hpp"

#include <algorithm>
#include <cstdint>
#include <string>

namespace digestive {
namespace detail {
enum class bit_order
{
    msb0, // most significant bit is bit 0
    lsb0 // least significant bit is bit 0
};

template<bit_order BO>
constexpr uint8_t last_byte_mask(std::uint8_t); template<>
constexpr uint8_t last_byte_mask<bit_order::lsb0>(std::uint8_t bits_to_keep)
{ return 0xFF >> (8-bits_to_keep); }
template<>
constexpr uint8_t last_byte_mask<bit_order::msb0>(std::uint8_t bits_to_keep)
{ return 0xFF << (8-bits_to_keep); }

template<
    typename    T,    // Element type of source array, e.g. uint64_t
    endian      E,    // Endianness to convert to for output
    std::size_t Bits, // Number of bits in digest
    bit_order   BO>
void extract_digest(const T* in, char* out)
{
    constexpr std::size_t full_elements = Bits / (8*sizeof(T));
    std::transform(in, in+full_elements, reinterpret_cast<T*>(out),
            [](T x){ return endian_converter<E,endian::host>()(x); });
    in += full_elements;
    out += full_elements * sizeof(T)/sizeof(char);

    constexpr std::size_t rem_bits = Bits - 8*sizeof(T)*full_elements;
    constexpr std::size_t rem_bytes = (rem_bits + 7) / 8;
    if (!rem_bytes)
        return;

    // Bits not a multiple of 64
    const T last_element = endian_converter<endian::host,E>()(*in);
    const char* last_element_ch = reinterpret_cast<const char*>(&last_element);
    out = std::copy(last_element_ch, last_element_ch+rem_bytes, out);

    constexpr std::uint8_t last_byte_bits = Bits & 7;
    if (!last_byte_bits)
        return;

    // Bits not a multiple of 8
    constexpr uint8_t mask = last_byte_mask<BO>(last_byte_bits);
    *out = static_cast<char>( static_cast<uint8_t>(*(out-1)) & mask );
}

} // namespace detail

template <std::size_t Bits>
struct digest {
    static constexpr std::size_t size = Bits;
    static constexpr std::size_t size_bytes = (Bits+7)/8;
    digest()=default;
    char m_digest[size_bytes]{};
    explicit operator std::string() const {
        static const char dec2hex[] = "0123456789abcdef";
        char buf[size_bytes*2+1];
        const char* in = m_digest;
        char* out = buf;
        for (const auto& byte : m_digest) {
            auto u8byte = static_cast<uint8_t>(byte);
            *out++ = dec2hex[u8byte >> 4];
            *out++ = dec2hex[u8byte & 0xF];
        }
        *out = '\0';
        return std::string(buf);
    }
};

} // namespace digestive

#endif // DIGESTIVE_DIGEST_HPP
