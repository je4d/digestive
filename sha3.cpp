#include "sha3.hpp"

#include <iostream>
#include <cassert>

template <typename T, typename D = digestive::digest<T>>
void test(const std::string& input, const std::string& digest)
{
    T dig;
    dig(input.data(), input.size());
    assert(std::string(D(dig)) == digest);
    assert(std::string(D(std::move(dig))) == digest);
}

int main(int argc, char** argv)
{
    test<digestive::sha3_224>("",
            "6b4e03423667dbb73b6e15454f0eb1ab"
            "d4597f9a1b078e3f5b5a6bc7");
    test<digestive::sha3_256>("",
            "a7ffc6f8bf1ed76651c14756a061d662"
            "f580ff4de43b49fa82d80a4b80f8434a");
    test<digestive::sha3_384>("",
            "0c63a75b845e4f7d01107d852e4c2485"
            "c51a50aaaa94fc61995e71bbee983a2a"
            "c3713831264adb47fb6bd1e058d5f004");
    test<digestive::sha3_512>("",
            "a69f73cca23a9ac5c8b567dc185a756e"
            "97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558"
            "f500199d95b6d3e301758586281dcd26");
    test<digestive::shake128<4096>>("",
            "7f9c2ba4e88f827d616045507605853e"
            "d73b8093f6efbc88eb1a6eacfa66ef26"
            "3cb1eea988004b93103cfb0aeefd2a68"
            "6e01fa4a58e8a3639ca8a1e3f9ae57e2"
            "35b8cc873c23dc62b8d260169afa2f75"
            "ab916a58d974918835d25e6a435085b2"
            "badfd6dfaac359a5efbb7bcc4b59d538"
            "df9a04302e10c8bc1cbf1a0b3a5120ea"
            "17cda7cfad765f5623474d368ccca8af"
            "0007cd9f5e4c849f167a580b14aabdef"
            "aee7eef47cb0fca9767be1fda69419df"
            "b927e9df07348b196691abaeb580b32d"
            "ef58538b8d23f87732ea63b02b4fa0f4"
            "873360e2841928cd60dd4cee8cc0d4c9"
            "22a96188d032675c8ac850933c7aff15"
            "33b94c834adbb69c6115bad4692d8619"
            "f90b0cdf8a7b9c264029ac185b70b83f"
            "2801f2f4b3f70c593ea3aeeb613a7f1b"
            "1de33fd75081f592305f2e4526edc096"
            "31b10958f464d889f31ba010250fda7f"
            "1368ec2967fc84ef2ae9aff268e0b170"
            "0affc6820b523a3d917135f2dff2ee06"
            "bfe72b3124721d4a26c04e53a75e30e7"
            "3a7a9c4a95d91c55d495e9f51dd0b5e9"
            "d83c6d5e8ce803aa62b8d654db53d09b"
            "8dcff273cdfeb573fad8bcd45578bec2"
            "e770d01efde86e721a3f7c6cce275dab"
            "e6e2143f1af18da7efddc4c7b70b5e34"
            "5db93cc936bea323491ccb38a388f546"
            "a9ff00dd4e1300b9b2153d2041d205b4"
            "43e41b45a653f2a5c4492c1add544512"
            "dda2529833462b71a41a45be97290b6f"
        );
}
