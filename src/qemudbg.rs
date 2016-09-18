/*
 * qemudbg
 * Implementation of a qemu debug IO port device
 */

use vm;
use std::fs::*;
use std::io::Write;
use std::cell::RefCell;
use std::rc::Rc;

const QEMUDBG_OUTPUT_FILE: &'static str = "qemudbg.out";

struct qemudbg 
{
    file: RefCell<File>,
}

impl vm::io_handler for qemudbg 
{

    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType 
    {
        assert!(size == 1);
        assert!(port == 0x402);
        unimplemented!();
    }

    fn io_write(&self, addr: u16, data: vm::IoOperandType) 
    {
        assert!(addr == 0x402);
        
        let c: char = data.unwrap_byte() as char;

        self.file.borrow_mut().write_fmt(format_args!("{}", c)).unwrap_or_else(|err| {
            error!("qemudbg: failed writing to file: {}", err);
        });
        
        // Output to debug console as well
        debug!("{}", data.unwrap_byte() as char);
    }
}

pub fn init()
{
    let dev = Rc::new(qemudbg {
        file: RefCell::new(File::create(QEMUDBG_OUTPUT_FILE).unwrap()),
    });

    vm::register_io_region(dev, 0x402, 1);
}

