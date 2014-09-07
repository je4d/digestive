#include "digester.hpp"

#include <iostream>

#include "digest.hpp"

struct algo
{
    using result_type = digestive::digest<algo>;
    static constexpr std::size_t digest_length = 32;
    static constexpr std::size_t rate = 64;
    using digest_generating_type = algo;

    void operator()(const char*, std::size_t)
    {
        ++m_calls;
    }

    explicit operator result_type() const &
    {
        digestive::digest<algo> ret;
        ret.m_digest[0] = 0xA1;
        ret.m_digest[1] = 0xB2;
        ret.m_digest[2] = 0xC3;
        ret.m_digest[3] = 0xD4;
        return ret;
    }

    std::size_t m_calls;
};

int main()
{
    digestive::digester<algo> dg;
    if(dg.hex_digest() != "a1b2c3d4")
        return 1;
    return 0;
}

