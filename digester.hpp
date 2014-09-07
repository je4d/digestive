#ifndef DIGESTIVE_DIGESTER_HPP
#define DIGESTIVE_DIGESTER_HPP

#include <algorithm>
#include <cstddef>
#include <string>

#include "digest.hpp"

namespace digestive {
namespace digester_detail {
template <typename T, typename U=T>
struct rate
{
    static constexpr std::size_t value = 4096;
};

template <typename T, std::size_t>
struct extract_rate
{
    using type = T;
};

template <typename T>
struct rate<T, typename extract_rate<T,T::rate>::type>
{
    static constexpr std::size_t value = T::rate;
    static_assert(value % 8 == 0, "Rate must be a multiple of 8");
};

}

template <typename T = void>
struct digester
{
    digester()=default;
    digester(const char* data)                   { add(data); }
    digester(const char* data, std::size_t size) { add(data, size); }
    digester(const std::string& str)             { add(str); }

    void add(const char* data)
    {
        static constexpr std::size_t rate = digester_detail::rate<T>::value;
        auto block_start = data;
        const char *block_end, *max_block_end;
        do {
            max_block_end = std::next(block_start, rate);
            block_end = std::find(block_start, max_block_end, '\0');
            m_algo(block_start, std::distance(block_start, block_end));
            block_start = max_block_end;
        } while (block_end == max_block_end);
    }
    void add(const char* data, std::size_t size) { m_algo(data, size); }
    void add(const std::string& str) { m_algo(str.data(), str.size()); }

    std::string hex_digest() const &
    {

        return std::string(digest<T>(m_algo));
    }

    std::string hex_digest() &&
    {
        return std::string(digest<T>(std::move(m_algo)));
    }


private:
    T m_algo;
};

} // namespace digestive

#endif // DIGESTIVE_DIGESTER_HPP

