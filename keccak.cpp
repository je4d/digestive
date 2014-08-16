#include "keccak.hpp"

#include <fstream>
#include <iostream>

template <typename T, typename D = typename T::digest>
void test(const char* data, std::size_t len)
{
    T dig;
    dig(data,len);
    D out(dig);
    std::string asHex(out);
    std::cout << asHex << "\n";
}

template <typename T, typename D = typename T::digest>
void test0bit() { test<T,D>("",0); }

template <typename T, typename D = typename T::digest>
void test135()
{
    T dig;
    dig("asdfas;dkjfal;ksdjflsadfasjfsakjf;lksajfd;lksajf;lkdsajf;lkdsaj;"
        "lkfjdsa;lkfjsalkfjsa;ldjflksdjflksajdflksajdf;lkjdsa;lfkjasdfdas"
        "dfsdssa",135);
    D out(dig);
    std::string asHex(out);
    std::cout << asHex << "\n";
}

int main(int argc, char** argv)
{

/*  hash-library bug test case
    digestive::keccak<digestive::keccak_256> digester;
    std::string a1(argv[1]);
    digester(a1.c_str(), a1.size());
    digestive::keccak_digest<digestive::keccak_256> digest(digester);
    std::cout << std::string(digest) << "\n";*/
    if (argc == 1) {
        test0bit<digestive::keccak_224>();
        test0bit<digestive::keccak_256>();
        test0bit<digestive::keccak_384>();
        test0bit<digestive::keccak_512>();
        test0bit<digestive::keccak_default<4096>>();
        test0bit<digestive::keccak_default<>,
                 digestive::digest<digestive::keccak_default<4096>>>();
    } else if (argc == 2) {
        std::ifstream file(argv[1], std::ios::in | std::ios::binary);
        char buf[1024];
        file.read(buf, 1024);
        std::size_t len = file.gcount();
        test<digestive::keccak_224>(buf, len);
        test<digestive::keccak_256>(buf, len);
        test<digestive::keccak_384>(buf, len);
        test<digestive::keccak_512>(buf, len);
        test<digestive::keccak_default<4096>>(buf, len);
        test<digestive::keccak_default<>,
             digestive::digest<digestive::keccak_default<4096>>>(buf, len);
    }
}
