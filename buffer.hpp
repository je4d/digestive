#ifndef DIGESTIVE_BUFFER_HPP
#define DIGESTIVE_BUFFER_HPP

#include <array>
#include <cstdint>
#include <iterator>

namespace digestive {
namespace detail {

template <std::size_t Bytes>
struct buffer
{
    buffer()=default;
    buffer(const buffer& o) :
        data(o.data),
        position{std::next(begin(data),o.position - begin(o.data))}
    {}
    buffer& operator=(const buffer& o)
    {
        data = o.data;
        position = std::next(begin(data),o.position - begin(o.data));
    }

    template <typename ProcessFn>
    void process(const char* input, std::size_t size, ProcessFn&& fn)
    {
        using namespace std;
        const char* const inputEnd = input + size;
        if (position != begin(data)) {
            const std::size_t space = end(data)-position;
            const char* copyUntil = input + min(space, size);
            position = copy(input, copyUntil, position);
            if (position == end(data)) {
                forward<ProcessFn>(fn)(begin(data));
                position = begin(data);
            }
            input = copyUntil;
        }
        while (not ((inputEnd - input) < Bytes)) {
            forward<ProcessFn>(fn)(input);
            input += Bytes;
        }
        position = copy(input, inputEnd, position);
    }
    std::array<char,Bytes>                    data;
    typename std::array<char,Bytes>::iterator position{begin(data)};
};
} // namespace detail
} // namespace digestive
#endif // DIGESTIVE_BUFFER_HPP
