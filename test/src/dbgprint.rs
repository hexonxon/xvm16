/*
 * Debug output
 */

use pio;
use core::fmt::Write;
use core::fmt::Result;

const QEMU_DBG_PORT: u16 = 0x402;

fn dbgwrite(buf: &[u8]) {
    for i in buf {
        unsafe { pio::outb(QEMU_DBG_PORT, *i); }
    }
}

pub struct DbgWriter
{
}

impl ::core::fmt::Write for DbgWriter
{
    fn write_str(&mut self, s: &str) -> Result {
        dbgwrite(s.as_bytes());
        Ok(())
    }
}

pub static mut WRITER: DbgWriter = DbgWriter {};

macro_rules! dbgprint {
    ($($arg:tt)*) => ({
        unsafe {
            use core::fmt::Write;
            dbgprint::WRITER.write_fmt(format_args!($($arg)*)).unwrap();
        }
    });
}

macro_rules! dbgprintln {
    ($fmt:expr) => (dbgprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (dbgprint!(concat!($fmt, "\n"), $($arg)*));
}
