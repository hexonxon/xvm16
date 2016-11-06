all: build

build:
	cargo build

run:
	cargo run

test:
	cargo test

check:
	make -C test && cargo run test/xvmtest; cat qemudbg.out

.PHONY: all run test check
