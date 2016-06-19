/*
 * CMOS IO handling
 */

use vm;

use std::rc::Rc;
use std::cell::RefCell;
use time;

const CMOS_SELECT_PORT: u16     = 0x70;
const CMOS_DATA_PORT: u16       = 0x71;
const CMOS_TOTAL_REGS: u8       = 128;  // Total number of byte registers we emulate
const CMOS_DEFAULT_SELECTOR: u8 = 0xD;  // Default selected register

/* 
 * Handled registers:
 * 0x00      Seconds
 * 0x02      Minutes
 * 0x04      Hours
 * 0x06      Weekday
 * 0x07      Day of Month
 * 0x08      Month
 * 0x09      Year
 * 0x32      Century (maybe)
 * 0x0A      Status Register A
 * 0x0B      Status Register B
 * 0x0D      Status Register D
 *
 * Current limitations:
 * - No BCD format, only binary mode
 * - No 12 hour support, only 24
 * - No interrupt generation
 * - RTC updates on every register access which can lead to unstable time readings in guests
 */
struct CMOS
{
    selector: u8,
    nmi_bit: bool, // TODO: this bit should be owned by vm/vcpu
    host_time: time::Tm,    // Real host time during last update
    time: time::Tm,         // Time we are emulating
}

impl CMOS
{
    fn new() -> CMOS 
    {
        CMOS {
            selector: CMOS_DEFAULT_SELECTOR,
            nmi_bit: false,
            host_time: time::empty_tm(),
            time: time::empty_tm(),
        }
    }

    fn nmi_mask(&self) -> u8
    {
        if self.nmi_bit {
            return 0x80;
        } else {
            return 0;
        }
    }

    fn read_selector(&mut self) -> u8
    {
        self.selector | self.nmi_mask()
    }

    fn write_selector(&mut self, val: u8) 
    {
        self.selector = val & 0x7F;
        self.nmi_bit = (val & 0x80) != 0;
    }

    // Returns current selector value and resets it to default
    fn reset_selector(&mut self) -> u8
    {
        let val = self.selector;
        self.selector = CMOS_DEFAULT_SELECTOR;
        return val;
    }

    fn read_reg(&mut self) -> u8
    {
        // Adjust emulated time by computing elapsed duration since last time 
        // Then add this duration to time we emulate
        let now = time::now();
        let delta = now - self.host_time; // Ok if negative

        self.time = self.time + delta;
        self.host_time = now;

        return match self.reset_selector() {
            // RTC
            // TODO: BCD?
            0x00 => self.time.tm_sec,
            0x02 => self.time.tm_min,
            0x04 => self.time.tm_hour,
            0x06 => self.time.tm_wday + 1, // CMOS wday starts from 1
            0x07 => self.time.tm_mday,
            0x08 => self.time.tm_mon,
            0x09 => self.time.tm_year % 100,
            0x32 => self.time.tm_year / 100,

            // Status
            0x0A => 0b00100110, // Default read only values, update bit always cleared
            0x0B => 0b00000110, // TODO: allow BCD and hour formats
            0x0D => 0b10000000,

            // Unsupported
            _ => 0,
        } as u8;
    }

    fn write_reg(&mut self, val: u8)
    {
        let v32 = val as i32;
        match self.reset_selector() {
            // RTC
            // TODO: BCD?
            0x00 => self.time.tm_sec    = v32,
            0x02 => self.time.tm_min    = v32,
            0x04 => self.time.tm_hour   = v32,
            0x06 => self.time.tm_wday   = v32 - 1, // CMOS wday starts from 1
            0x07 => self.time.tm_mday   = v32,
            0x08 => self.time.tm_mon    = v32,
            0x09 => self.time.tm_year   = self.time.tm_year / 100 * 100 + v32,
            0x32 => self.time.tm_year   = v32 * 100 + self.time.tm_year % 100,

            // Unsupported
            _ => (),
        };
    }
}

// Test initial state
#[test] fn cmos_test_default() 
{
    let cmos = CMOS::new();

    assert!(cmos.selector == CMOS_DEFAULT_SELECTOR);
    assert!(cmos.nmi_bit == false);
    assert!(cmos.host_time == time::empty_tm());
    assert!(cmos.time == time::empty_tm());
}


// Check that NMI bit is propogated to selector value
#[test] fn cmos_test_nmi_bit()
{
    let mut cmos = CMOS::new();

    let mut sel = cmos.read_selector();
    assert!(sel & 0x80 == 0);
    
    cmos.write_selector(sel | 0x80);
    sel = cmos.read_selector();
    assert!(sel & 0x80 != 0);

    cmos.write_selector(sel & 0x7F);
    sel = cmos.read_selector();
    assert!(sel & 0x80 == 0);
}

// TODO: MOAR TESTS

///////////////////////////////////////////////////////////////////////////////

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
        assert!(cmos.selector < CMOS_TOTAL_REGS);

        match port {
            CMOS_SELECT_PORT => {
                return vm::IoOperandType::byte(cmos.read_selector());
            },

            CMOS_DATA_PORT => {
                return vm::IoOperandType::byte(cmos.read_reg());
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

        assert!(cmos.selector < CMOS_TOTAL_REGS);

        match port {
            CMOS_SELECT_PORT => {
                cmos.write_selector(val);
            }

            CMOS_DATA_PORT => {
                cmos.write_reg(val);
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
        cmos: RefCell::new(CMOS::new()),
    });

    vm::register_io_region(vm, dev.clone(), CMOS_SELECT_PORT, 1);
    vm::register_io_region(vm, dev.clone(), CMOS_DATA_PORT, 1);
}

