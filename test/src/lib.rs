#![feature(lang_items, asm, naked_functions, core_intrinsics)]
#![no_std]

#[macro_use]
mod dbgprint;
#[macro_use]
mod arch;
mod pio;

use arch::*;

#[no_mangle]
pub extern fn rust_main() {
    dbgprintln!("Hello God. This is me, Jesus.");
    dbgprintln!("Interrupts are {}", match interrupts_enabled() {
                    true => "enabled",
                    false => "disabled"
                });

    assert!(!interrupts_enabled());

    arch_init();

    assert!(false);
}

#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] extern fn panic_fmt() -> ! {loop{}}

