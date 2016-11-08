TESTS := $(patsubst test/payload/%.rs,%,$(wildcard test/payload/*.rs))

all: build

build:
	cargo build

run:
	cargo run

test:
	cargo test
	cargo build
	make -C test
	for i in $(TESTS) ; do \
		echo "Running $$i ..." ;\
		cargo run test/payload/$$i.bin ;\
	done

clean:
	cargo clean
	make -C test clean

.PHONY: all run test check clean
