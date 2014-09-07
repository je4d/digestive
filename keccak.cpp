#include "keccak.hpp"

#include <bandit/bandit.h>
using namespace bandit;

template <typename T, typename D = digestive::digest<T>>
void test(const std::string& input, const std::string& digest)
{
    T dig;
    dig(input.data(), input.size());
    AssertThat(std::string(D(dig)), Equals(digest));
    AssertThat(std::string(D(std::move(dig))), Equals(digest));
}

go_bandit([](){
    it("works", [](){
        test<digestive::keccak_224>("",
                "f71837502ba8e10837bdd8d365adb855"
                "91895602fc552b48b7390abd");
        test<digestive::keccak_256>("",
                "c5d2460186f7233c927e7db2dcc703c0"
                "e500b653ca82273b7bfad8045d85a470");
        test<digestive::keccak_384>("",
                "2c23146a63a29acf99e73b88f8c24eaa"
                "7dc60aa771780ccc006afbfa8fe2479b"
                "2dd2b21362337441ac12b515911957ff");
        test<digestive::keccak_512>("",
                "0eab42de4c3ceb9235fc91acffe746b2"
                "9c29a8c366b7c60e4e67c466f36a4304"
                "c00fa9caf9d87976ba469bcbe06713b4"
                "35f091ef2769fb160cdab33d3670680e");
        test<digestive::keccak<4096>>("",
                "6753e3380c09e385d0339eb6b050a68f"
                "66cfd60a73476e6fd6adeb72f5edd7c6"
                "f04a5d017a19cbe291935855b4860f69"
                "df04c98aa78b407a9ba9826f7266ef14"
                "ba6d3f90c4fe154d27c2858ea6db8c11"
                "7411a1bc5c499410c391b298f37bf636"
                "b0f5c31dbd6487a7d3d8cf2a97b61969"
                "7e66d894299b8b4d80e0498538e18544"
                "c3a2fa33f0bfb1cfef8da7875c4967f3"
                "32c7fc93c050e81fb404f9a91503d601"
                "0ee16f50b4ed0bc563ba8431668b003d"
                "7e2e6f226cb7fa93bb2e132c861fdc21"
                "41457589a63ecf05481126a7c2de941a"
                "2fdec71cb70de81887b9014223865e79"
                "c4ffe82dae83c1fc484b9a07a7e52b13"
                "5f4ae3a0e09247ea4e2625e9349b0ac7"
                "3f24cb418df6dcb49ca37860298ada18"
                "aa23595b5096ef789de3edf3826817ff"
                "f4f71102a01e1d2599f2958d5c186f5b"
                "11f5feedb61bb732dbb42d18b1e77258"
                "a8f211bf95c9f47f19603ec419ff879a"
                "ea41a4811344d016bbc4f9496741c469"
                "cca425c5be73543219af40796c0b9ff1"
                "4aeaa70c5e22e4bb1346a3ddfedd8a55"
                "9104e4704f1227d42918ae3f7404fbf3"
                "c6340a486e776aabcc34190f87da4bd9"
                "54b83386255a0e34df05ca2e781faf6f"
                "e66475852481fce20798a56629abfac4"
                "08760ce64606008a3b568c88aba1c6df"
                "3381e0765567ea84b2ce4b441cf1eefa"
                "a32125d5139361a632b3008566a2e8af"
                "1055cb06ae462b6bf87b34a9770618e6"
            );
    });
});

int main(int argc, char** argv)
{
    return bandit::run(argc, argv);
}
