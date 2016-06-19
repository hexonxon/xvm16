/*
 * CMOS IO handling
 */

use vm;
use std::rc::Rc;
use std::cell::RefCell;

const CMOS_SELECT_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16   = 0x71;
const CMOS_TOTAL_REGS: u8   = 128;  // Total number of byte registers we emulate
const CMOS_DEFAULT_REG: u8  = 0xD;  // Default selected register

struct CMOS
{
    regs: [u8; CMOS_TOTAL_REGS as usize],
    next_reg: u8,
    nmi_bit: bool, // TODO: this bit should be owned by vm/vcpu
}

impl CMOS {
    fn nmi_mask(&self) -> u8 {
        if self.nmi_bit {
            return 0x80;
        } else {
            return 0;
        }
    }

    // Returns current next_reg value and resets it to default
    fn reset_next_reg(&mut self) -> u8 {
        let val = self.next_reg;
        self.next_reg = CMOS_DEFAULT_REG;
        return val;
    }
}

struct CMOSDev
{
    cmos: RefCell<CMOS>,
}


impl vm::io_handler for CMOSDev
{
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType
    {
        let mut cmos = self.cmos.borrow_mut();

        assert!(size == 1);
        assert!(cmos.next_reg < CMOS_TOTAL_REGS);

        match port {
            CMOS_SELECT_PORT => {
                return vm::IoOperandType::byte(cmos.next_reg | cmos.nmi_mask());
            },

            CMOS_DATA_PORT => {
                let reg = cmos.reset_next_reg();
                return vm::IoOperandType::byte(cmos.regs[reg as usize]);
            }

            _ => {
                panic!();
            }
        }
    }


    fn io_write(&self, port: u16, data: vm::IoOperandType) 
    {
        let mut cmos = self.cmos.borrow_mut();
        let val: u8 = data.unwrap_byte();

        assert!(cmos.next_reg < CMOS_TOTAL_REGS);

        match port {
            CMOS_SELECT_PORT => {
                cmos.next_reg = val & 0x7F;
                cmos.nmi_bit = (val & 0x80) != 0;
            }

            CMOS_DATA_PORT => {
                let reg = cmos.reset_next_reg();
                cmos.regs[reg as usize] = val;
            }

            _ => {
                panic!();
            }
        }
    }
}

pub fn init(vm: &mut vm::vm) 
{ 
	let dev = Rc::new(CMOSDev {
        cmos: RefCell::new(CMOS {
            regs: [0; CMOS_TOTAL_REGS as usize],
            next_reg: CMOS_DEFAULT_REG,
            nmi_bit: false, // NMI enabled
        }),
    });

    vm::register_io_region(vm, dev.clone(), CMOS_SELECT_PORT, 1);
    vm::register_io_region(vm, dev.clone(), CMOS_DATA_PORT, 1);
}

