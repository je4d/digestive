all: sha3_test_clang sha3_test_gcc keccak_test_clang keccak_test_gcc
HEADERS = digest.hpp endian.hpp buffer.hpp
sha3_test_gcc: sha3.cpp sha3.hpp keccak_core.hpp $(HEADERS) Makefile
	g++ -g -o $@ -std=c++11 -fsanitize=address -Wall -Werror $<
sha3_test_clang: sha3.cpp sha3.hpp keccak_core.hpp $(HEADERS) Makefile
	clang++ -g -o $@ -std=c++11 -fsanitize=address -fsanitize=undefined -Wall -Werror $<
keccak_test_gcc: keccak.cpp keccak.hpp keccak_core.hpp $(HEADERS) Makefile
	g++ -g -o $@ -std=c++11 -fsanitize=address -Wall -Werror $<
keccak_test_clang: keccak.cpp keccak.hpp keccak_core.hpp $(HEADERS) Makefile
	clang++ -g -o $@ -std=c++11 -fsanitize=address -fsanitize=undefined -Wall -Werror $<
