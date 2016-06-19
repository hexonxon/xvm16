/*
 * qemudbg
 * Implementation of a qemu debug IO port device
 */

use vm;
use std::fs::*;
use std::io::Write;

const QEMUDBG_OUTPUT_FILE: &'static str = "qemudbg.out";

struct qemudbg {
    file: File,
}

impl vm::io_handler_ops for qemudbg {
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType {
        assert!(size == 1);
        assert!(port == 0x402);
        unimplemented!();
    }

    fn io_write(&mut self, addr: u16, data: vm::IoOperandType) {
        assert!(addr == 0x402);
        
        let c: char = data.unwrap_byte() as char;

        self.file.write_fmt(format_args!("{}", c)).unwrap_or_else(|err| {
            error!("qemudbg: failed writing to file: {}", err);
        });

        // Output to debug console as well
        debug!("{}", data.unwrap_byte() as char);
    }
}

pub fn init(vm: &mut vm::vm)
{
    let dev = Box::new(qemudbg {
        file: File::create(QEMUDBG_OUTPUT_FILE).unwrap(),
    });

    vm::register_io_handler(vm, dev, 0x402, 1);
}
