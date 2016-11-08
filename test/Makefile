#
# For each test payload we build a separate bootable kernel.
# Each kernel is made out of a common library (xvmtest), common boot code (boot.o) and payload library
#

TARGET := i686-unknown-linux-gnu
BUILD := debug
LIBDIR := target/$(TARGET)/$(BUILD)
LIB := $(LIBDIR)/libxvmtest.a
OBJS := boot.o
CROSS_PREFIX ?= i386-elf-
TESTS := $(patsubst payload/%.rs,%,$(wildcard payload/*.rs))

all: payload

%.o: src/%.asm
	nasm -f elf32 -o $@ $<

cargo:
	rustup override add nightly
	cargo build --target i686-unknown-linux-gnu --verbose

payload: $(OBJS) src/xvmtest.lds cargo
	for i in $(TESTS) ; do \
		rustc -L crate=$(LIBDIR) -L dependency=$(LIBDIR)/deps/ --crate-type staticlib --target $(TARGET) --out-dir payload payload/$$i.rs;\
		$(CROSS_PREFIX)ld --gc-sections -T src/xvmtest.lds -o payload/$$i.elf $(OBJS) payload/lib$$i.a ;\
		$(CROSS_PREFIX)objcopy -j .text -j .data -O binary payload/$$i.elf payload/$$i.bin ;\
	done

clean:
	cargo clean
	rm -f $(OBJS)
	for i in $(TESTS) ; do \
		rm -f payload/lib$$i.a payload/$$i.elf payload/$$i.bin ;\
	done

.PHONY: all cargo clean payload
