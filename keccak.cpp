#include "keccak.hpp"

#include <fstream>
#include <iostream>

template <typename T, typename D = typename T::digest>
void test0bit()
{
    T dig;
    dig("",0);
    D out(dig);
    std::string asHex(out);
    std::cout << asHex << "\n";
}

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
    test0bit<digestive::keccak<digestive::keccak_224>>();
    test0bit<digestive::keccak<digestive::keccak_256>>();
    test0bit<digestive::keccak<digestive::keccak_384>>();
    test0bit<digestive::keccak<digestive::keccak_512>>();
//    test0bit<digestive::keccak<digestive::shake128>,
//                digestive::keccak_digest<digestive::shake128,4096>>();
//    test0bit<digestive::keccak<digestive::shake256>,
//                digestive::keccak_digest<digestive::shake256,4096>>();
    test135<digestive::keccak<digestive::keccak_256>>();

/*  hash-library bug test case
    digestive::keccak<digestive::keccak_256> digester;
    std::string a1(argv[1]);
    digester(a1.c_str(), a1.size());
    digestive::keccak_digest<digestive::keccak_256> digest(digester);
    std::cout << std::string(digest) << "\n";*/
    if (argc > 1) {
        std::ifstream file(argv[1], std::ios::in | std::ios::binary);
        char buf[1024];
        file.read(buf, 1024);
        digestive::keccak<digestive::keccak_256> k256;
        k256(buf, 135);
        digestive::keccak<digestive::keccak_256>::digest dk256(k256);
        std::cout << std::string(dk256) << "\n";
    }
}
