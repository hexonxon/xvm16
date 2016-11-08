#![no_std]

#[macro_use]
extern crate xvmtest;

use xvmtest::dbgprint;

#[no_mangle]
pub extern "C" fn test_main() {
    dbgprintln!("This is a dummy test payload");
}
