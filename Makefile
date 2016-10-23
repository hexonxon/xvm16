all: run

run:
	cargo run

test:
	cargo test

check:
	make -C test && cargo run test/xvmtest

.PHONY: all run test check
