KERNEL := xvmtest.bin
IMG := xvmtest
LIB := target/i686-unknown-linux-gnu/debug/libxvmtest.a
OBJS := boot.o
CROSS_PREFIX ?= i386-elf-

all: $(IMG)

$(IMG): $(KERNEL)
	$(CROSS_PREFIX)objcopy -j .text -j .data -O binary $< $@

$(KERNEL): $(OBJS) src/xvmtest.lds cargo
	$(CROSS_PREFIX)ld --gc-sections -T src/xvmtest.lds -o $@ $(OBJS) $(LIB)

%.o: src/%.asm
	nasm -f elf32 -o $@ $<

cargo:
	rustup override add nightly
	cargo build --target i686-unknown-linux-gnu --verbose

clean:
	cargo clean
	rm -rf $(KERNEL) $(BOOT)

.PHONY: all cargo clean
