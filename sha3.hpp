#ifndef DIGESTIVE_SHA3_H
#define DIGESTIVE_SHA3_H

#include "buffer.hpp"
#include "digest.hpp"
#include "endian.hpp"
#include "keccak_core.hpp"

namespace digestive {

template <typename T, std::size_t DigestLength>
struct sha3_fix : private keccak_core::keccak<DigestLength*2>
{
private:
    static constexpr std::size_t capacity = DigestLength*2;
    using base = keccak_core::keccak<capacity>;

public:
    using digest = digestive::digest<T>;
    static constexpr std::size_t digest_length = DigestLength;
    using digest_generating_type = sha3_fix;
    using base::operator();

    explicit operator digest() const &
    {
        return digest(sha3_fix(*this));
    }

    explicit operator digest() &&
    {
        // Sha3(M) = Keccak(M || 01) = process(M || 01 || 10*1), in LSB0
        keccak_core::finalize<capacity,0x6>(this->m_buffer,this->m_state);
        digest ret;
        keccak_core::extract_digest<capacity,digest_length>(this->m_state,
                                                            ret.m_digest);
        return ret;
    }
};

template <typename T, std::size_t Capacity>
struct sha3_xof;

template <template<std::size_t>class TT, std::size_t DigestLength,
                                         std::size_t Capacity>
struct sha3_xof<TT<DigestLength>, Capacity> :
    private keccak_core::keccak<Capacity>,
    keccak_core::xof_digest_typedef<TT<DigestLength>>
{
    using base = keccak_core::keccak<Capacity>;
public:
    using digest_generating_type = sha3_xof;
    using base::operator();

    template <std::size_t Length>
    explicit operator digestive::digest<TT<Length>>() const &
    {
        return digest<TT<Length>>(sha3_xof(*this));
    }

    template <std::size_t Length>
    explicit operator digest<TT<Length>>() &&
    {
        // Shake*(M) = Keccak(M || 1111) = process(M || 1111 || 10*1), in LSB0
        // 0x1f = 0b00011111
        keccak_core::finalize<Capacity,0x1f>(this->m_buffer,this->m_state);
        digestive::digest<TT<Length>> ret;
        char* digest_out = sha3_xof<TT<Length>,Capacity>::priv_digest(ret);
        keccak_core::extract_digest<Capacity,Length>(this->m_state, digest_out);
        return ret;
    }

private:
    template <std::size_t Length>
    static char* priv_digest(digestive::digest<TT<Length>>& digest)
    { return digest.m_digest; }
    template <typename,std::size_t>
    friend struct sha3_xof;
};

struct sha3_224 : sha3_fix<sha3_224,224> {};
struct sha3_256 : sha3_fix<sha3_256,256> {};
struct sha3_384 : sha3_fix<sha3_384,384> {};
struct sha3_512 : sha3_fix<sha3_512,512> {};
template <std::size_t DigestLength = 0>
struct shake128 : sha3_xof<shake128<DigestLength>,256> {};
template <std::size_t DigestLength = 0>
struct shake256 : sha3_xof<shake256<DigestLength>,512> {};

} // namespace digestive

#endif // DIGESTIVE_SHA3_H
