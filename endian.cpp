#include "endian.hpp"
#include <endian.h>

int main()
{
    if ((digestive::detail::endianness == digestive::detail::endian::little)
            != (__BYTE_ORDER == __LITTLE_ENDIAN))
        return 1;
    if ((digestive::detail::endianness == digestive::detail::endian::big)
            != (__BYTE_ORDER == __BIG_ENDIAN))
        return 1;
    std::uint64_t x = 0x7766554433221100;
    std::uint64_t y = digestive::detail::endian_converter<
        digestive::detail::endian::host,
        digestive::detail::endian::big>()(x);
    return y ?  0 : 1;
}
