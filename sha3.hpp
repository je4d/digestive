#ifndef DIGESTIVE_SHA3_H
#define DIGESTIVE_SHA3_H

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"
#include "keccak_core.hpp"

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
class sha3_digest;

namespace sha3_detail {
    template <sha3_output Output, std::size_t DigestLength>
    using traits_fix = keccak_core::traits_fix<DigestLength,
                                                 sha3_digest<Output>>;
    template <sha3_output Output, std::size_t Capacity>
    struct sha3_xof_traits_holder {
        template <std::size_t XofBits>
        using type = sha3_digest<Output,XofBits>;
        using traits = keccak_core::traits_xof<Capacity, type>;
    };
    template <sha3_output Output, std::size_t Capacity>
    using traits_xof = typename sha3_xof_traits_holder<Output,Capacity>::traits;

    template <sha3_output Output>
    struct traits;
    template<>struct traits<sha3_224>:traits_fix<sha3_224,224>{};
    template<>struct traits<sha3_256>:traits_fix<sha3_256,256>{};
    template<>struct traits<sha3_384>:traits_fix<sha3_384,384>{};
    template<>struct traits<sha3_512>:traits_fix<sha3_512,512>{};
    template<>struct traits<shake128>:traits_xof<shake128,256>{};
    template<>struct traits<shake256>:traits_xof<shake256,512>{};
} // namespace sha3_detail

template <sha3_output Output, std::size_t XofBits>
class sha3_digest : digest<XofBits>
{
    static_assert(sha3_detail::traits<Output>::extendable,
            "XofBits should not only be explicitly set for sha3_digest in "
            "shake128/shake256 modes");
    template <typename,typename,bool> friend class sha3_outputfn;
    using digest = typename sha3_digest::digest;
public:
    using digest::operator std::string;
};

template <sha3_output Output>
class sha3_digest<Output,0> : digest<sha3_detail::traits<Output>::digest_length>
{
    template <typename,typename,bool> friend class sha3_outputfn;
    using base = typename sha3_digest::digest;
public:
    using base::operator std::string;
};

template <typename Sha3, typename Traits, bool Extendable>
class sha3_outputfn
{
public:
    using digest = typename Traits::digest;
    static constexpr std::size_t rate = Traits::rate;

    explicit operator digest() const &
    {
        const Sha3* realThis{static_cast<const Sha3*>(this)};
        return digest(Sha3(*realThis));
    }

    explicit operator digest() &&
    {
        digest ret;
        Sha3* realThis{static_cast<Sha3*>(this)};
        auto& buffer = realThis->m_buffer.data();
        auto position = realThis->m_buffer.position;
        // Sha3(M) = Keccak(M || 01) = process(M || 01 || 10*1), in LSB0
        *position++ = 0x6;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_core::process<Traits::rate>(realThis->m_state.array, buffer);
        keccak_core::extract_digest<rate>(realThis->m_state.array, ret);
        return ret;
    }
};

template <typename Sha3, typename Traits>
class sha3_outputfn<Sha3,Traits,true>
{
    static constexpr std::size_t rate = Traits::rate;
public:
    template <std::size_t XofBits>
    using digest = typename Traits::template digest<XofBits>;

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
        digest ret;
        Sha3* realThis{static_cast<Sha3*>(this)};
        auto& buffer = realThis->m_buffer.data();
        auto position = realThis->m_buffer.position;
        // Shake*(M) = Keccak(M || 1111) = process(M || 1111 || 10*1), in LSB0
        *position++ = 0x1F;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_core::process<rate>(realThis->m_state.array, buffer);
        keccak_core::extract_digest<rate>(realThis->m_state.array, ret);
        return ret;
    }
};

template <sha3_output Output>
class sha3 : public sha3_outputfn<sha3<Output>,
                                  sha3_detail::traits<Output>,
                                  sha3_detail::traits<Output>::extendable>
{
    using traits = typename sha3_detail::traits<Output>;
public:
    void operator()(const char* data, size_t size)
    {
        m_buffer.process(data, size, [&](const char* block){
                keccak_core::process<traits::rate>(m_state.array, block);
        });
    }

private:
    keccak_core::state           m_state;
    detail::buffer<traits::rate/8> m_buffer;
    friend class sha3::sha3_outputfn;
};

} // namespace digestive

#endif // DIGESTIVE_SHA3_H
