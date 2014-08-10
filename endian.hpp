#ifndef DIGESTIVE_ENDIAN_HPP
#define DIGESTIVE_ENDIAN_HPP

#include <cstdint>

#ifndef _MSC_VER
#include <endian.h>
#endif

namespace digestive {
namespace detail {

using std::uint64_t;
using std::uint32_t;

enum class endian {
    little,
    big,
    host,
    network = big,
    unknown
};

alignas (uint32_t) static constexpr const char testval[] = "\xAA\xBB\xCC\xDD";
static const uint32_t endianness_test_value
    = *reinterpret_cast<const uint32_t*>(testval);
static const endian endianness =
    endianness_test_value == 0xAABBCCDD
        ? endian::big
        : endianness_test_value == 0xDDCCBBAA
            ? endian::little
            : endian::unknown;

inline uint8_t endian_swap(uint8_t x)
{
    return x;
}

inline uint16_t endian_swap(uint16_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(x);
#elif defined(MSC_VER)
    return _byteswap_uint16(x);
#else
    return  (x >>  8) | (x <<  8);
#endif
}

inline uint32_t endian_swap(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#elif defined(MSC_VER)
    return _byteswap_uint32(x);
#else
    return  (x >> 24) |
           ((x >>  8) & 0x0000FF00ULL) |
           ((x <<  8) & 0x00FF0000ULL) |
            (x << 24);
#endif
}

inline uint64_t endian_swap(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(x);
#elif defined(MSC_VER)
  return _byteswap_uint64(x);
#else
  return  (x >> 56) |
      ((x >> 40) & 0x000000000000FF00ULL) |
      ((x >> 24) & 0x0000000000FF0000ULL) |
      ((x >>  8) & 0x00000000FF000000ULL) |
      ((x <<  8) & 0x000000FF00000000ULL) |
      ((x << 24) & 0x0000FF0000000000ULL) |
      ((x << 40) & 0x00FF000000000000ULL) |
      (x << 56);
#endif
}

template <endian From, endian To>
struct endian_converter {};
inline uint64_t endian_convert(uint64_t);
template <> struct endian_converter<endian::host,   endian::little> {
template <typename T> inline T operator()(T x)
{ return (endianness == endian::little) ? x : endian_swap(x); } };
template <> struct endian_converter<endian::host,   endian::big   > {
template <typename T> inline T operator()(T x)
{ return (endianness == endian::big) ? x : endian_swap(x); } };
template <> struct endian_converter<endian::little, endian::host  > {
template <typename T> inline T operator()(T x)
{ return (endianness == endian::little) ? x : endian_swap(x); } };
template <> struct endian_converter<endian::big,    endian::host  > {
template <typename T> inline T operator()(T x)
{ return (endianness == endian::big) ? x : endian_swap(x); } };
template <> struct endian_converter<endian::big,    endian::little> {
template <typename T> inline T operator()(T x)
{ return endian_swap(x); } };
template <> struct endian_converter<endian::little, endian::big   > {
template <typename T> inline T operator()(T x)
{ return endian_swap(x); } };

template <typename T> inline T endian_host_to_little(T x)
{ return endian_converter<endian::host,   endian::little>()(x); }
template <typename T> inline T endian_host_to_big   (T x)
{ return endian_converter<endian::host,   endian::big   >()(x); }
template <typename T> inline T endian_little_to_host(T x)
{ return endian_converter<endian::little, endian::host  >()(x); }
template <typename T> inline T endian_big_to_host   (T x)
{ return endian_converter<endian::big,    endian::host  >()(x); }
template <typename T> inline T endian_big_to_little (T x)
{ return endian_converter<endian::big,    endian::little>()(x); }
template <typename T> inline T endian_little_to_big (T x)
{ return endian_converter<endian::little, endian::big   >()(x); }


} // namespace detail
} // namespace digestive
#endif // DIGESTIVE_ENDIAN_HPP
