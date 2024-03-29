#ifndef DIGESTIVE_KECCAK_CORE_HPP
#define DIGESTIVE_KECCAK_CORE_HPP

#include <cstdint>
#include <iterator>
#include <algorithm>

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"

namespace digestive {
namespace keccak_core {

template <std::size_t Capacity>
struct traits
{
    static constexpr std::size_t width = 1600;
    static constexpr std::size_t capacity = Capacity;
    static constexpr std::size_t rate = width-capacity;
    static_assert(Capacity%64 == 0, "Keccak's Rate and Capacity must be "
                                    "multiples of 64");
    static_assert(rate%64 == 0,     "Keccak's Rate and Capacity must be "
                                    "multiples of 64");
};

constexpr unsigned int rounds = 24;
constexpr uint64_t xor_masks[rounds] {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/// rotate left and wrap around to the right
inline uint64_t rotateLeft(uint64_t x, uint8_t numBits)
{
    return (x << numBits) | (x >> (64 - numBits));
}

/// return x % 5 for 0 <= x <= 9
constexpr unsigned int mod5(unsigned int x)
{
    return (x < 5) ? x : x - 5;
}

struct state : std::array<uint64_t,1600/64> {};

void permute(state& state)
{
    // re-compute state
    for (unsigned int round = 0; round < rounds; round++)
    {
        // Theta
        uint64_t coefficients[5];
        for (unsigned int i = 0; i < 5; i++)
            coefficients[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                              state[i + 15] ^ state[i + 20];

        for (unsigned int i = 0; i < 5; i++)
        {
            uint64_t one = coefficients[mod5(i + 4)] ^
                           rotateLeft(coefficients[mod5(i + 1)], 1);
            state[i     ] ^= one;
            state[i +  5] ^= one;
            state[i + 10] ^= one;
            state[i + 15] ^= one;
            state[i + 20] ^= one;
        }

        // temporary
        uint64_t one;

        // Rho Pi
        uint64_t last = state[1];
        one = state[10]; state[10] = rotateLeft(last,  1); last = one;
        one = state[ 7]; state[ 7] = rotateLeft(last,  3); last = one;
        one = state[11]; state[11] = rotateLeft(last,  6); last = one;
        one = state[17]; state[17] = rotateLeft(last, 10); last = one;
        one = state[18]; state[18] = rotateLeft(last, 15); last = one;
        one = state[ 3]; state[ 3] = rotateLeft(last, 21); last = one;
        one = state[ 5]; state[ 5] = rotateLeft(last, 28); last = one;
        one = state[16]; state[16] = rotateLeft(last, 36); last = one;
        one = state[ 8]; state[ 8] = rotateLeft(last, 45); last = one;
        one = state[21]; state[21] = rotateLeft(last, 55); last = one;
        one = state[24]; state[24] = rotateLeft(last,  2); last = one;
        one = state[ 4]; state[ 4] = rotateLeft(last, 14); last = one;
        one = state[15]; state[15] = rotateLeft(last, 27); last = one;
        one = state[23]; state[23] = rotateLeft(last, 41); last = one;
        one = state[19]; state[19] = rotateLeft(last, 56); last = one;
        one = state[13]; state[13] = rotateLeft(last,  8); last = one;
        one = state[12]; state[12] = rotateLeft(last, 25); last = one;
        one = state[ 2]; state[ 2] = rotateLeft(last, 43); last = one;
        one = state[20]; state[20] = rotateLeft(last, 62); last = one;
        one = state[14]; state[14] = rotateLeft(last, 18); last = one;
        one = state[22]; state[22] = rotateLeft(last, 39); last = one;
        one = state[ 9]; state[ 9] = rotateLeft(last, 61); last = one;
        one = state[ 6]; state[ 6] = rotateLeft(last, 20); last = one;
        state[ 1] = rotateLeft(last, 44);

        // Chi
        for (unsigned int j = 0; j < 25; j += 5)
        {
            // temporaries
            uint64_t one = state[j];
            uint64_t two = state[j + 1];

            state[j]     ^= state[j + 2] & ~two;
            state[j + 1] ^= state[j + 3] & ~state[j + 2];
            state[j + 2] ^= state[j + 4] & ~state[j + 3];
            state[j + 3] ^= one          & ~state[j + 4];
            state[j + 4] ^= two          & ~one;
        }

        // Iota
        state[0] ^= xor_masks[round];
    }
}

template <std::size_t Capacity>
void process(state& state, const char* block)
{
    constexpr auto rate = traits<Capacity>::rate;
    const std::uint64_t* data64 = reinterpret_cast<const std::uint64_t*>(block);
    using namespace std;
    transform(begin(state), next(begin(state),rate/64), data64, begin(state),
            [](std::uint64_t a, std::uint64_t b) {
                return a^detail::endian_host_to_little(b);
            });
    permute(state);
}

template <std::size_t Capacity, uint8_t LeadBits, std::size_t BufSize>
void finalize(detail::buffer<BufSize>& buffer, state& state)
{
    auto position = buffer.position;
    *position++ = LeadBits;
    std::fill(position, std::end(buffer.data), 0ull);
    *std::prev(std::end(buffer.data)) |= 0x80;
    process<Capacity>(state, begin(buffer.data));
}

template <std::size_t Capacity, std::size_t DigestLength>
void extract_digest(state& state, char* digest_out)
{
    if (DigestLength == 0)
        return;
    constexpr auto rate = traits<Capacity>::rate;
    std::size_t bits = DigestLength;
    while (bits > rate) {
        detail::extract_digest<
                std::uint64_t,
                detail::endian::little,
                rate,
                detail::bit_order::lsb0
            >(begin(state), digest_out);
        digest_out += rate/8;
        bits -= rate;
        permute(state);
    }
    detail::extract_digest<
            std::uint64_t,
            detail::endian::little,
            (DigestLength-1) % rate + 1,
            detail::bit_order::lsb0
        >(begin(state), digest_out);
};

namespace adl_shield
{
template <std::size_t Capacity>
struct keccak
{
    void operator()(const char* data, size_t size)
    {
        m_buffer.process(data, size, [&](const char* block){
                process<Capacity>(m_state, block);
        });
    }

    state                                    m_state{};
    detail::buffer<traits<Capacity>::rate/8> m_buffer;
};

template <typename T>
struct xof_result_type;

template <template<std::size_t>class TT, std::size_t DigestLength>
struct xof_result_type<TT<DigestLength>>
{
    using result_type = digestive::digest<TT<DigestLength>>;
    static constexpr std::size_t digest_length = DigestLength;
};

template <template<std::size_t>class TT>
struct xof_result_type<TT<0>>
{
    template <std::size_t DigestLength>
    using result_type = digestive::digest<TT<DigestLength>>;
};

}

template <std::size_t Capacity>
using keccak = adl_shield::keccak<Capacity>;

template <typename T>
using xof_result_type = adl_shield::xof_result_type<T>;

} // namespace keccak_core
} // namespace digestive
#endif // DIGESTIVE_KECCACK_CORE_HPP
