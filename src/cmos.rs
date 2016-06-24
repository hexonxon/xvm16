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
    sta: u8,
    stb: u8,
    nmi_bit: bool,          // TODO: this bit should be owned by vm/vcpu
    host_time: time::Tm,    // Real host time during last update
    time: time::Tm,         // Time we are emulating
}

impl CMOS
{
    fn new() -> CMOS 
    {
        CMOS {
            selector: CMOS_DEFAULT_SELECTOR,
            sta: 0b00100110,
            stb: 0b00000110,
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

    fn to_rtc_format(&self, val: i32) -> u8
    {
        if (self.stb & 0x04) == 0 {
            // BCD format needed
            assert!(val < 100);
            let lo = (val % 10) as u8;
            let hi = (val / 10) as u8;
            return lo | (hi << 4);
        } else {
            return val as u8;
        }
    }

    fn from_rtc_format(&self, val: u8) -> i32
    {
        if (self.stb & 0x04) == 0 {
            // BCD format needed
            let lo = (val & 0xF) as i32;
            let hi = (val >> 4) as i32;
            return lo + hi;
        } else {
            return val as i32;
        }
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
            0x00 => self.to_rtc_format(self.time.tm_sec),
            0x02 => self.to_rtc_format(self.time.tm_min),
            0x04 => self.to_rtc_format(self.time.tm_hour),
            0x06 => self.to_rtc_format(self.time.tm_wday + 1), // CMOS wday starts from 1
            0x07 => self.to_rtc_format(self.time.tm_mday),
            0x08 => self.to_rtc_format(self.time.tm_mon),
            0x09 => self.to_rtc_format(self.time.tm_year % 100),
            0x32 => self.to_rtc_format(self.time.tm_year / 100),

            // Status
            0x0A => self.sta,
            0x0B => self.stb,

            // Unsupported
            _ => 0,
        } as u8;
    }

    fn write_reg(&mut self, val: u8)
    {
        match self.reset_selector() {
            // RTC
            0x00 => self.time.tm_sec    = self.from_rtc_format(val),
            0x02 => self.time.tm_min    = self.from_rtc_format(val),
            0x04 => self.time.tm_hour   = self.from_rtc_format(val),
            0x06 => self.time.tm_wday   = self.from_rtc_format(val) - 1, // CMOS wday starts from 1
            0x07 => self.time.tm_mday   = self.from_rtc_format(val),
            0x08 => self.time.tm_mon    = self.from_rtc_format(val),
            0x09 => self.time.tm_year   = self.from_rtc_format(val) + self.time.tm_year / 100 * 100,
            0x32 => self.time.tm_year   = self.from_rtc_format(val) * 100 + self.time.tm_year % 100,

            // Status
            0x0A => self.sta = val,
            0x0B => self.stb = val,

            // Unsupported
            _ => (),
        };
    }
}

#[cfg(test)]
mod cmos_test {

    use super::CMOS;
    use time;

    fn read_reg(cmos: &mut CMOS, reg: u8) -> u8
    {
        let sel = (cmos.read_selector() & 0x80) | reg;
        cmos.write_selector(sel);
        return cmos.read_reg();
    }

    fn write_reg(cmos: &mut CMOS, reg: u8, val: u8)
    {
        let sel = (cmos.read_selector() & 0x80) | reg;
        cmos.write_selector(sel);
        cmos.write_reg(val);
    }

    fn read_rtc_reg(cmos: &mut CMOS, is_bcd: bool, reg: u8) -> u8
    {
        let mut val = read_reg(cmos, reg);

        if is_bcd {
            let lo = val & 0xF;
            let hi = val >> 4;
            val = hi * 10 + lo;
        }

        return val;

    }

    fn set_bcd(cmos: &mut CMOS, is_bcd: bool)
    {
        let stb = read_reg(cmos, 0x0b);
        if is_bcd {
            write_reg(cmos, 0x0b, stb | 0x04u8);
        } else {
            write_reg(cmos, 0x0b, stb & !0x04u8);
        }
    }

    // Test initial state
    #[test] fn default()
    {
        let cmos = CMOS::new();

        assert!(cmos.selector == super::CMOS_DEFAULT_SELECTOR);
        assert!(cmos.nmi_bit == false);
        assert!(cmos.host_time == time::empty_tm());
        assert!(cmos.time == time::empty_tm());
    }


    // Check that NMI bit is propogated to selector value
    #[test] fn nmi_bit()
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


    fn rtc_to_tm(cmos: &mut CMOS) -> time::Tm
    {
        let is_bcd = (read_reg(cmos, 0x0b) & 0x04) == 0;

        let mut tm: time::Tm = time::empty_tm();
        tm.tm_sec = read_rtc_reg(cmos, is_bcd, 0x00) as i32;
        tm.tm_min = read_rtc_reg(cmos, is_bcd, 0x02) as i32;
        tm.tm_hour = read_rtc_reg(cmos, is_bcd, 0x04) as i32;
        tm.tm_wday = read_rtc_reg(cmos, is_bcd, 0x06) as i32;
        tm.tm_mday = read_rtc_reg(cmos, is_bcd, 0x07) as i32;
        tm.tm_mon = read_rtc_reg(cmos, is_bcd, 0x08) as i32;
        tm.tm_year = (read_rtc_reg(cmos, is_bcd, 0x32) as i32) * 100 + (read_rtc_reg(cmos, is_bcd, 0x09) as i32);

        return tm;
    }

    fn rtc_test_common(cmos: &mut CMOS)
    {
        // Time reported by rtc should be within sane distance from now
        let now = time::now();
        let t = rtc_to_tm(cmos);
        assert!((t - now).num_seconds() <= 1);

        // Check that eventually rtc will report a monotonic increase in time
        loop {
            let tm1 = rtc_to_tm(cmos);
            let tm2 = rtc_to_tm(cmos);
            if tm2 > tm1 {
                break;
            }
        }
    }

    #[test] fn rtc()
    {
        let mut cmos = CMOS::new();

        set_bcd(&mut cmos, true);
        rtc_test_common(&mut cmos);

        set_bcd(&mut cmos, false);
        rtc_test_common(&mut cmos);
    }
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

