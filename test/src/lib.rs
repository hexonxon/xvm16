#![feature(lang_items, asm)]
#![no_std]

extern crate rlibc;

mod pio;
#[macro_use] mod dbgprint;

#[no_mangle]
pub extern fn rust_main() {
    dbgprintln!("Hello God. This is me, Jesus.");
    assert!(false);
}

#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] extern fn panic_fmt() -> ! {loop{}}

