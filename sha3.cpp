#include "sha3.hpp"

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
    test0bit<digestive::sha3<digestive::sha3_224>>();
    test0bit<digestive::sha3<digestive::sha3_256>>();
    test0bit<digestive::sha3<digestive::sha3_384>>();
    test0bit<digestive::sha3<digestive::sha3_512>>();
    test0bit<digestive::sha3<digestive::shake128>,
                digestive::sha3_digest<digestive::shake128,4096>>();
    test0bit<digestive::sha3<digestive::shake256>,
                digestive::sha3_digest<digestive::shake256,4096>>();
    test135<digestive::sha3<digestive::sha3_256>>();

/*  hash-library bug test case
    digestive::sha3<digestive::sha3_256> digester;
    std::string a1(argv[1]);
    digester(a1.c_str(), a1.size());
    digestive::sha3_digest<digestive::sha3_256> digest(digester);
    std::cout << std::string(digest) << "\n";*/
}
