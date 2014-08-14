#ifndef DIGESTIVE_KECCAK_H
#define DIGESTIVE_KECCAK_H

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"
#include "keccak_core.hpp"

namespace digestive {

enum keccak_output {
    keccak_224,
    keccak_256,
    keccak_384,
    keccak_512,
    keccak_default
};

template <keccak_output Output, std::size_t XofBits=0>
class keccak_digest;

namespace keccak_detail {
    template <keccak_output Output, std::size_t DigestLength>
    using traits_fix = keccak_core::traits_fix<DigestLength,
                                                 keccak_digest<Output>>;
    template <keccak_output Output, std::size_t Capacity>
    struct traits_xof_impl {
        template <std::size_t XofBits>
        using type = keccak_digest<Output,XofBits>;
        using traits = keccak_core::traits_xof<Capacity, type>;
    };
    template <keccak_output Output, std::size_t Capacity>
    using traits_xof = typename traits_xof_impl<Output,Capacity>::traits;

    template <keccak_output Output>
    struct traits;
    template<>struct traits<keccak_224    >:traits_fix<keccak_224,    224>{};
    template<>struct traits<keccak_256    >:traits_fix<keccak_256,    256>{};
    template<>struct traits<keccak_384    >:traits_fix<keccak_384,    384>{};
    template<>struct traits<keccak_512    >:traits_fix<keccak_512,    512>{};
    template<>struct traits<keccak_default>:traits_xof<keccak_default,576>{};
} // namespace keccak_detail

template <keccak_output Output, std::size_t XofBits>
class keccak_digest : digest<XofBits>
{
    static_assert(keccak_detail::traits<Output>::extendable,
            "XofBits should not only be explicitly set for keccak_digest in "
            "variable-length digest mode");
    template <typename,typename,bool> friend class keccak_outputfn;
    using digest = typename keccak_digest::digest;
public:
    using digest::operator std::string;
};

template <keccak_output Output>
class keccak_digest<Output,0>
    : digest<keccak_detail::traits<Output>::digest_length>
{
    template <typename,typename,bool> friend class keccak_outputfn;
    using base = typename keccak_digest::digest;
public:
    using base::operator std::string;
};

template <typename Sha3, typename Traits, bool Extendable>
class keccak_outputfn
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
        *position++ = 0x1;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_core::process<rate>(realThis->m_state.array, buffer);
        keccak_core::extract_digest<rate>(realThis->m_state.array, ret);
        return ret;
    }
};

template <typename Sha3, typename Traits>
class keccak_outputfn<Sha3,Traits,true>
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
        using digest = keccak_outputfn::digest<XofBits>;
        digest ret;
        Sha3* realThis{static_cast<Sha3*>(this)};
        auto& buffer = realThis->m_buffer.data();
        auto position = realThis->m_buffer.position;
        *position++ = 0x1;
        std::fill(position, std::end(buffer), 0ull);
        *std::prev(std::end(buffer)) |= 0x80;
        keccak_core::process<rate>(realThis->m_state.array, buffer);
        keccak_core::extract_digest<rate>(realThis->m_state.array, ret);
        return ret;
    }
};

template <keccak_output Output>
class keccak : public keccak_outputfn<keccak<Output>,
                                      keccak_detail::traits<Output>,
                                      keccak_detail::traits<Output>::extendable>
{
    using traits = typename keccak_detail::traits<Output>;
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
    friend class keccak::keccak_outputfn;
};

} // namespace digestive

#endif // DIGESTIVE_KECCAK_H
