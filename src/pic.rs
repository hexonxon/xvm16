/*
 * PIC emulation
 */

use vm;

use std::rc::Rc;
use std::cell::RefCell;

const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

/*
 * Single i8259 PIC chip
 */
struct I8259A
{
    imr: u8,
    isr: u8,
    offset: u8,
    mask: u8,
    icw1: u8,
    icw3: u8,
    next_icw: usize,
}

impl I8259A 
{
    fn default() -> I8259A {
        I8259A { 
            imr: 0,
            isr: 0,
            offset: 0,
            mask: 0xff,
            icw1: ICW1_INIT | ICW1_ICW4,
            icw3: 0,
            next_icw: 0,
        }
    }

    fn is_initialized(&self) -> bool {
        self.next_icw == 1
    }

    fn command(&mut self, cmd: u8) {
        if cmd & ICW1_INIT != 0 {
            /* 
             * Start initialization 
             * We support only ICW1 + ICW4
             */
            assert!(cmd & !(ICW1_INIT | ICW1_ICW4) == 0);
            self.icw1 = cmd;
            self.next_icw = 2;
        }
    }

    fn read(&mut self) -> u8 {
        self.mask
    }

    fn write(&mut self, data: u8) {
        match self.next_icw {
            2 => {
                self.offset = data;
                self.next_icw = 3;
            },

            3 => {
                self.icw3 = data;
                if self.icw1 & ICW1_ICW4 != 0 {
                    self.next_icw = 4;
                } else {
                    self.next_icw = 1;
                }
            },

            4 => {
                assert!(data == ICW4_8086); /* Just check that ICW4 is the only one we support */
                self.next_icw = 1;
            },

            _ => {
                self.mask = data; /* Writes go to mask by default */
            }
        }
    }
}

#[cfg(test)]
mod i8259a_test 
{
    use super::I8259A;

    fn init(offset: u8, mask: u8, cascade: u8, use_icw4: bool) -> I8259A {
        let mut dev = I8259A::default();
        assert!(!dev.is_initialized());

        if use_icw4 {
            dev.command(super::ICW1_INIT | super::ICW1_ICW4);
        } else {
            dev.command(super::ICW1_INIT);
        }
        assert!(!dev.is_initialized());

        dev.write(offset);
        assert!(!dev.is_initialized());

        dev.write(cascade);

        if use_icw4 {
            assert!(!dev.is_initialized());
            dev.write(super::ICW4_8086);
        }

        assert!(dev.is_initialized());

        dev.write(mask);
        assert!(dev.read() == mask);

        return dev;
    }

    /* Init with ICW4 */
    #[test] fn init_icw4() {
        let mut dev = init(0x08, 0xAB, 0x02, true);
    }

    /* Init without ICW4 */
    #[test] fn init_no_icw4() {
        let mut dev = init(0x08, 0xAB, 0x02, true);
    }
}

struct PIC 
{
    master: I8259A,
    slave: I8259A,
}

impl PIC
{
    fn new() -> PIC {
        PIC {
            master: I8259A::default(),
            slave: I8259A::default(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

struct PICDev
{
    pic: RefCell<PIC>,
}

impl vm::io_handler for PICDev
{
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType
    {
        assert!(size == 1);

        let mut dev = self.pic.borrow_mut();
        vm::IoOperandType::byte(
            match port {
                PIC_MASTER_DATA => dev.master.read(),
                PIC_SLAVE_DATA => dev.slave.read(),
                _ => 0,
            }
        )
    }


    fn io_write(&self, port: u16, data: vm::IoOperandType)
    {
        let mut dev = self.pic.borrow_mut();
        let data8 = data.unwrap_byte();

        match port {
            PIC_MASTER_DATA => dev.master.write(data8),
            PIC_SLAVE_DATA => dev.slave.write(data8),
            PIC_MASTER_CMD => dev.master.command(data8),
            PIC_SLAVE_CMD => dev.slave.command(data8),
            _ => panic!(),
        }
    }
}

pub fn init()
{
	let dev = Rc::new(PICDev {
        pic: RefCell::new(PIC::new()),
    });

    vm::register_io_region(dev.clone(), PIC_MASTER_CMD, 1);
    vm::register_io_region(dev.clone(), PIC_MASTER_DATA, 1);
    vm::register_io_region(dev.clone(), PIC_SLAVE_CMD, 1);
    vm::register_io_region(dev.clone(), PIC_SLAVE_DATA, 1);
}

