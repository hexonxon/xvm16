#![feature(lang_items, asm, naked_functions, core_intrinsics)]
#![no_std]

extern crate rlibc;

#[macro_use] pub mod dbgprint;
#[macro_use] mod arch;
pub mod pio;
mod pic;
mod pit;

use arch::*;

const PIC_MASTER_OFFSET: u8 = 0x20;
const PIC_SLAVE_OFFSET: u8 = 0x70;

extern "C" fn unhandled_interrupt() {
    dbgprintln!("Unhandled interrupt");
}

extern "C" fn unhandled_exception(vec: u8, frame: *mut arch::ExceptionFrame, error: u32) {
    unsafe {
        let frameaddr = frame as u32;
        dbgprintln!("Unhandled exception {:x}, frame at {:X}, CS:EIP {:X}:{:X}, EFL {:X}, code {:X}",
                    vec,
                    frameaddr,
                    (*frame).cs,
                    (*frame).eip,
                    (*frame).eflags,
                    error);
    }
    loop {}
}

extern "C" fn exp_debug(frame: *mut arch::ExceptionFrame) {
    unhandled_exception(1, frame, 0);
}

extern "C" fn exp_double_fault(frame: *mut arch::ExceptionFrame, error: u32) {
    unhandled_exception(8, frame, error);
}

extern {
    fn test_main();
}

#[no_mangle]
pub extern fn rust_main() {
    dbgprintln!("Hello God. This is me, Jesus.");
    dbgprintln!("Interrupts are {}", match interrupts_enabled() {
                    true => "enabled",
                    false => "disabled"
                });

    assert!(!interrupts_enabled());

    arch_init();

    // Configure exceptions
    exception_handler!(3, exp_debug);
    exception_handler_with_error!(8, exp_double_fault);

    // Configure interrupts
    pic::reset(pic::make_arg(PIC_MASTER_OFFSET, PIC_SLAVE_OFFSET), 0xFFFF);
    for i in 0..16 {
        interrupt_handler!(pic::get_interrupt_vector(i), unhandled_interrupt);
    }

    pic::set_mask(0);
    arch::interrupts_enable();
    dbgprintln!("Interrupts configured");

    unsafe {
        test_main();
    }
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

