#ifndef DIGESTIVE_SHA3_H
#define DIGESTIVE_SHA3_H

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"
#include "keccak_detail.hpp"

namespace digestive {

enum sha3_output {
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    shake128,
    shake256
};

template <sha3_output Output, std::size_t XofBits=0>
struct sha3_digest;

namespace sha3_detail {
    template <sha3_output Output>
    struct traits;

    template <sha3_output Output, size_t DigestLength>
    struct traits_fix
    {
        static constexpr bool extendable = false;
        static constexpr size_t capacity = 2*DigestLength;
        static constexpr size_t rate = 1600-capacity;
        static constexpr size_t digest_length = DigestLength;
        using digest = sha3_digest<Output>;
    };

    template <sha3_output Output, size_t Capacity>
    struct traits_xof
    {
        static constexpr bool extendable = true;
        static constexpr size_t capacity = Capacity;
        static constexpr size_t rate = 1600-capacity;
        template <std::size_t XofBits>
        using digest = sha3_digest<Output,XofBits>;
    };

    template<>struct traits<sha3_224>:traits_fix<sha3_224,224>{};
    template<>struct traits<sha3_256>:traits_fix<sha3_256,256>{};
    template<>struct traits<sha3_384>:traits_fix<sha3_384,384>{};
    template<>struct traits<sha3_512>:traits_fix<sha3_512,512>{};
    template<>struct traits<shake128>:traits_xof<shake128,256>{};
    template<>struct traits<shake256>:traits_xof<shake256,512>{};
} // namespace sha3_detail

template <sha3_output Output, std::size_t XofBits>
struct sha3_digest : private digest<XofBits>
{
    static_assert(sha3_detail::traits<Output>::extendable,
            "XofBits should not only be explicitly set for sha3_digest in "
            "shake128/shake256 modes");

    using base = typename sha3_digest::digest;
    using base::operator std::string;
    sha3_digest()=default;

private:
    template <typename,typename,bool> friend class sha3_outputfn;
};

template <sha3_output Output>
struct sha3_digest<Output,0> :
    private digest<sha3_detail::traits<Output>::digest_length>
{
    using base = typename sha3_digest::digest;
    using base::operator std::string;

    sha3_digest()=default;

private:
    template <typename,typename,bool> friend class sha3_outputfn;
};

template <typename Sha3, typename Traits, bool Extendable>
class sha3_outputfn
{
public:
    using digest = typename Traits::digest;

    explicit operator digest() const &
    {
        const Sha3* realThis{static_cast<const Sha3*>(this)};
        return digest(Sha3(*realThis));
    }

    explicit operator digest() &&
    {
        // sha3 has LSB0 bit ordering.
        //
        // note: || is bit-concatenation, * is 0 or more repetitions
        // Sha3(M) = Keccak(M || 01)
        // Keccak(M) = process(M || 10*1)
        //
        // Therefore we need to append 0110*1 to the message
        // This means either 01100001 = 0x6 | 0x80 = 0x86,
        // or 0x01100000 [ null bytes ... ] 0x0000001

        Sha3* realThis{static_cast<Sha3*>(this)};
        auto& buffer = realThis->m_buffer.data();
        auto position = realThis->m_buffer.position;
        *position++ = 0x6;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_detail::process<Traits::rate>(realThis->m_state.array, buffer);

        auto& state_array = realThis->m_state.array;
        digest ret;
        detail::extract_digest<
                std::uint64_t,
                detail::endian::little,
                digest::size,
                detail::bit_order::lsb0
            >(state_array, ret.m_digest);
        return ret;
    }
};

template <typename Sha3, typename Traits>
class sha3_outputfn<Sha3,Traits,true>
{
    using traits = Traits;

public:
    template <std::size_t XofBits>
    using digest = typename traits::template digest<XofBits>;

    template <std::size_t XofBits>
    explicit operator digest<XofBits>() const &
    {
        const Sha3* realThis{static_cast<const Sha3*>(this)};
        return digest<XofBits>(Sha3(*realThis));
    }

    template <std::size_t XofBits>
    explicit operator digest<XofBits>() &&
    {
        using digest = sha3_outputfn::digest<XofBits>;

        // sha3 has LSB0 bit ordering. See note above.
        Sha3* realThis{static_cast<Sha3*>(this)};
        auto& buffer = realThis->m_buffer.data();
        auto position = realThis->m_buffer.position;
        // M || 1111 10*1
        *position++ = 0x1F;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_detail::process<Traits::rate>(realThis->m_state.array, buffer);

        std::size_t bits = digest::size;
        auto& state_array = realThis->m_state.array;
        digest ret;
        char* digest_out = ret.m_digest;
        while (bits > Sha3::traits::rate) {
            detail::extract_digest<
                    std::uint64_t,
                    detail::endian::little,
                    Sha3::traits::rate,
                    detail::bit_order::lsb0
                >(state_array, digest_out);
            digest_out += Sha3::traits::rate/8;
            bits -= Sha3::traits::rate;
            keccak_detail::permute(state_array);
        }
        detail::extract_digest<
                std::uint64_t,
                detail::endian::little,
                digest::size % Sha3::traits::rate,
                detail::bit_order::lsb0
            >(state_array, digest_out);
        return ret;
    }
};

template <sha3_output Output>
class sha3 : public sha3_outputfn<sha3<Output>,
                                  sha3_detail::traits<Output>,
                                  sha3_detail::traits<Output>::extendable>
{
    using traits = typename sha3_detail::traits<Output>;
    using outputfn = typename sha3::sha3_outputfn;

public:

    void operator()(const char* data, size_t size)
    {
        m_buffer.process(data, size, [&](const char* block){
                keccak_detail::process<traits::rate>(m_state.array, block);
        });
    }

private:
    static constexpr std::size_t state_size = 1600 / 64;
    static constexpr std::size_t rate = traits::rate;

    struct state_t {
        uint64_t array[state_size]{};
    };
    state_t  m_state;
    detail::buffer<traits::rate/8> m_buffer;

    friend class sha3::sha3_outputfn;
};

} // namespace digestive

#endif // DIGESTIVE_SHA3_H
