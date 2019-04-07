GCC_BIN ?= $(shell which gcc)
CARGO_BIN ?= $(shell which cargo)

build:
	$(CARGO_BIN) build --release
	$(GCC_BIN) -o ./examples/mock_f ./examples/pfring_mock_f.c -Isrc  -L. -l:target/release/libTLSParse.so

run: clean build
	./examples/hello

clean:
	$(CARGO_BIN) clean
	rm -f ./examples/hello
