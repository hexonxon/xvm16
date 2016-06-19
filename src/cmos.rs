/*
 * CMOS IO handling
 */

use vm;
use std::sync::Arc;

const CMOS_SELECT_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;
const CMOS_TOTAL_REGS: usize = 128;

struct CMOS 
{
    regs: [u8; CMOS_TOTAL_REGS],
    next_reg: usize,
    next_reg_set: bool,  
}

impl vm::io_handler_ops for CMOS 
{

    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType 
    {
        assert!(size == 1);

        match port {
            // Reads from select port are invalid
            CMOS_SELECT_PORT => {
                return vm::IoOperandType::make_unhandled(1);
            },

            // Read from data port
            CMOS_DATA_PORT => {
                if !self.next_reg_set {
                    warn!("CMOS: attempted read when data reg is not set");
                    return vm::IoOperandType::make_unhandled(1);
                }
                    
                assert!(self.next_reg < CMOS_TOTAL_REGS);
                return vm::IoOperandType::byte(self.regs[self.next_reg]);
            }

            _ => {
                panic!();
            }
        }
    }


    fn io_write(&mut self, port: u16, data: vm::IoOperandType) 
    {
    }
}

pub fn init(vm: &mut vm::vm) 
{ 
	let dev = Arc::new(CMOS {
        regs: [0; CMOS_TOTAL_REGS],
        next_reg: 0,
        next_reg_set: false,
    });

    vm::register_io_handler(vm, dev, CMOS_SELECT_PORT, 1);
    vm::register_io_handler(vm, dev, CMOS_DATA_PORT, 1);
}

