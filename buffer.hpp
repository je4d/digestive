#ifndef DIGESTIVE_BUFFER_HPP
#define DIGESTIVE_BUFFER_HPP

#include <cstdint>
#include <iterator>

namespace digestive {
namespace detail {
template <std::size_t Bytes>
struct buffer
{
    buffer()=default;
    buffer(const buffer& o) :
        data{o.data},
        position{data.data+(o.position-o.data.data)}
    {}
    buffer& operator=(const buffer& o)
    {
        data = o.data;
        position = data() + (o.position - o.data());
    }

    template <typename ProcessFn>
    void process(const char* input, std::size_t size, ProcessFn&& fn)
    {
        using namespace std;
        const char* const inputEnd = input + size;
        if (position != begin(data())) {
            const std::size_t space = end(data())-position;
            const char* copyUntil = input + min(space, size);
            position = copy(input, copyUntil, position);
            if (position == end(data())) {
                forward<ProcessFn>(fn)(data());
                position = begin(data());
            }
            input = copyUntil;
        }
        while (not ((inputEnd - input) < Bytes)) {
            forward<ProcessFn>(fn)(input);
            input += Bytes;
        }
        position = copy(input, inputEnd, position);
    }
    struct data_t {
        char data[Bytes]{};
        typedef char array[Bytes];
        array& operator()() { return data; }
        const array& operator()() const { return data; }
//        char (&operator()())[Bytes] { return data; }
//        const char (&operator()())[Bytes] const { return data; }
    };
    data_t data;
    char* position{data()};
};
} // namespace detail
} // namespace digestive
#endif // DIGESTIVE_BUFFER_HPP
