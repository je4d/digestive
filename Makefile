all: test
HEADERS = digest.hpp endian.hpp buffer.hpp
CXXFLAGS = -g -std=c++11 -fsanitize=address -Wall -Werror -I external
sha3_test_gcc: sha3.cpp sha3.hpp keccak_core.hpp $(HEADERS) Makefile
	g++ -o $@ $(CXXFLAGS) $<
sha3_test_clang: sha3.cpp sha3.hpp keccak_core.hpp $(HEADERS) Makefile
	clang++ -o $@ $(CXXFLAGS) -fsanitize=undefined $<
keccak_test_gcc: keccak.cpp keccak.hpp keccak_core.hpp $(HEADERS) Makefile
	g++ -o $@ $(CXXFLAGS)  $<
keccak_test_clang: keccak.cpp keccak.hpp keccak_core.hpp $(HEADERS) Makefile
	clang++ -o $@ $(CXXFLAGS) -fsanitize=undefined $<
digester_test_gcc: digester.cpp digester.hpp digest.hpp
	g++ -o $@ $(CXXFLAGS)  $<
digester_test_clang: digester.cpp digester.hpp digest.hpp
	clang++ -o $@ $(CXXFLAGS) -fsanitize=undefined $<

test: \
	run-sha3_test_gcc \
	run-sha3_test_clang \
	run-keccak_test_gcc \
	run-keccak_test_clang \
	run-digester_test_gcc \
	run-digester_test_clang

run-%: %
	@(./$* && echo '$*:\tpass' || (echo '$*:\tfail'; false))|expand -t30
