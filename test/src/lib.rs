#![feature(lang_items, asm, naked_functions, core_intrinsics)]
#![no_std]

extern crate rlibc;

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
    interrupt_handler!(0x20, unhandled_interrupt);
    exception_handler!(0x1, exp_debug);
    exception_handler_with_error!(0x8, exp_double_fault);
    unsafe {
        asm!("int 1"::::"intel");
    }

    assert!(false);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
        loop {}
}

#[lang = "eh_personality"]
extern fn eh_personality() {
}

#[lang = "panic_fmt"]
extern fn panic_fmt() -> ! {
    loop{}
}

