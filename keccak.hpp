#ifndef DIGESTIVE_KECCAK_H
#define DIGESTIVE_KECCAK_H

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"
#include "keccak_core.hpp"

namespace digestive {

template <typename T, std::size_t DigestLength>
struct keccak_fix : private keccak_core::keccak<DigestLength*2>
{
private:
    static constexpr std::size_t capacity = DigestLength*2;
    using base = keccak_core::keccak<capacity>;

public:
    using digest = digestive::digest<T>;
    static constexpr std::size_t digest_length = DigestLength;
    using digest_generating_type = keccak_fix;
    using base::operator();

    explicit operator digest() const &
    {
        return digest(keccak_fix(*this));
    }

    explicit operator digest() &&
    {
        keccak_core::finalize<capacity,0x1>(this->m_buffer,this->m_state);
        digest ret;
        keccak_core::extract_digest<capacity,digest_length>(this->m_state,
                                                            ret.m_digest);
        return ret;
    }
};

template <typename T, std::size_t Capacity>
struct keccak_xof;

template <template<std::size_t>class TT, std::size_t DigestLength,
                                         std::size_t Capacity>
struct keccak_xof<TT<DigestLength>, Capacity> :
    private keccak_core::keccak<Capacity>,
    keccak_core::xof_digest_typedef<TT<DigestLength>>
{
    using base = keccak_core::keccak<Capacity>;
public:
    using digest_generating_type = keccak_xof;
    using base::operator();

    template <std::size_t Length>
    explicit operator digestive::digest<TT<Length>>() const &
    {
        return digest<TT<Length>>(keccak_xof(*this));
    }

    template <std::size_t Length>
    explicit operator digest<TT<Length>>() &&
    {
        keccak_core::finalize<Capacity,0x1>(this->m_buffer,this->m_state);
        digestive::digest<TT<Length>> ret;
        char* digest_out = keccak_xof<TT<Length>,Capacity>::priv_digest(ret);
        keccak_core::extract_digest<Capacity,Length>(this->m_state, digest_out);
        return ret;
    }

private:
    template <std::size_t Length>
    static char* priv_digest(digestive::digest<TT<Length>>& digest)
    { return digest.m_digest; }
    template <typename,std::size_t>
    friend struct keccak_xof;
};

struct keccak_224     : keccak_fix<keccak_224,    224> {};
struct keccak_256     : keccak_fix<keccak_256,    256> {};
struct keccak_384     : keccak_fix<keccak_384,    384> {};
struct keccak_512     : keccak_fix<keccak_512,    512> {};
template <std::size_t DigestLength = 0>
struct keccak_default : keccak_xof<keccak_default<DigestLength>,576> {};

} // namespace digestive

#endif // DIGESTIVE_KECCAK_H
