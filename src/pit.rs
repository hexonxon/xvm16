/*
 * PIT emulation
 */

use vm;

use std::rc::Rc;
use std::cell::RefCell;
use time;

// PIT internal oscilator freq
const PIT_FREQ_HZ: u64 = 1193182;
const PIT_FREQ_MHZ: f64 = 1.193182;

// PIT IO ports
const PIT_CH0:u16 = 0x40;
const PIT_CH1:u16 = 0x41;
const PIT_CH2:u16 = 0x42;
const PIT_CMD:u16 = 0x43;

// Mode/Command bits 6-7
const PIT_SELECT_CH0: u8 = 0b00;
const PIT_SELECT_CH1: u8 = 0b01;
const PIT_SELECT_CH2: u8 = 0b10;
const PIT_SELECT_READBACK: u8 = 0b11;

// Mode/command bits 4-5
const PIT_ACCESS_LATCH_COUNT: u8 = 0b00;
const PIT_ACCESS_LOBYTE: u8 = 0b01;
const PIT_ACCESS_HIBYTE: u8 = 0b10;
const PIT_ACCESS_LOBYTE_HIBYTE: u8 = 0b11;

// Mode/command bits 1-3
const PIT_MODE_0: u8 = 0b000;
const PIT_MODE_1: u8 = 0b001;
const PIT_MODE_2: u8 = 0b010;
const PIT_MODE_3: u8 = 0b011;
const PIT_MODE_4: u8 = 0b100;
const PIT_MODE_5: u8 = 0b101;
const PIT_MODE_ALT_2: u8 = 0b110; // Same as mode 2, just different bit value
const PIT_MODE_ALT_3: u8 = 0b111; // Same as mode 3, just different bit value

// Mode/command bit 0
const PIT_BCD_MODE: u8 = 0b0;
const PIT_BINARY_MODE: u8 = 0b1;

// PIT mode decoded from register byte for convinience
#[derive(Default)]
struct PITModeReg
{
    select: u8,
    access: u8,
    mode: u8,
    is_bcd: bool,
}

impl PITModeReg
{
    fn from(val: u8) -> PITModeReg
    {
        let mut res = PITModeReg::default();

        res.is_bcd = (val & 0x1) == PIT_BCD_MODE;

        res.mode = (val >> 1) & 0x7;
        if res.mode == PIT_MODE_ALT_2 {
            res.mode = PIT_MODE_2;
        } else if res.mode == PIT_MODE_ALT_3 {
            res.mode = PIT_MODE_3;
        }

        res.access = (val >> 4) & 0x3;
        res.select = (val >> 6) & 0x3;

        return res;
    }
}

// TODO: better names for modes
#[derive(Copy, Clone, PartialEq)]
enum PITChannelMode
{
    Mode0,
    Mode1,
    Mode2,
    Mode3,
    Mode4,
    Mode5,
}

#[derive(Copy, Clone, PartialEq)]
enum PITChannelState
{
    Initial,    // Initial uninitialized state
    WaitLo,     // Waiting for reload value to be set (based on access mode)
    WaitHi,     // Waiting for reload value to be set (based on access mode)
    Enabled,    // Enabled and counting
}

#[derive(Copy, Clone, PartialEq)]
enum PITChannelAccess
{
    // TODO: Initial?
    LoByte,     // Low byte is read/written
    HiByte,     // Hi byte is read/written
    Word,       // Low byte then hi byte
}

#[derive(Copy, Clone)]
struct PITChannel
{
    reload: u16,
    count: u16,
    latch: u16,
    mode: PITChannelMode,
    state: PITChannelState,
    access: PITChannelAccess,
    read_more: bool,        // There is 1 more byte to read
    read_latch: bool,       // Next read should be from latch instead of count
    time: time::Timespec,   // Last update time
}

impl PITChannel
{
    fn default() -> PITChannel {
        PITChannel {
            reload: 0,
            count: 0,
            latch: 0,
            mode: PITChannelMode::Mode0,
            state: PITChannelState::Initial,
            access: PITChannelAccess::Word,
            read_more: false,
            read_latch: false,
            time: time::empty_tm().to_timespec(),
        }
    }

    /*
     * Set new access mode and reset channel state
     */
    fn reset(&mut self, mode: PITChannelMode, access: PITChannelAccess) {
        self.access = access;
        self.mode = mode;
        self.state = match access {
            PITChannelAccess::HiByte =>
                PITChannelState::WaitHi,
            _ =>
                PITChannelState::WaitLo,
        };
        self.reload = 0; // TODO: does reload reset to 0 actually?
        self.read_more = false;
        self.read_latch = false;
    }

    /*
     * Update stored value based on operation mode and elapsed ticks
     */
    fn update(&mut self) {
        if self.state != PITChannelState::Enabled {
            return;
        }

        let time = time::now().to_timespec();
        let delta_mms = (time - self.time).num_microseconds().unwrap();
        assert!(delta_mms > 0);

        let ticks = ((delta_mms as f64) * PIT_FREQ_MHZ) as u64;

        let mut delta_ticks = 0;
        if self.reload == 0 {
            delta_ticks = ((ticks % 0x10000) as u16);
        } else {
            delta_ticks =  ((ticks % self.reload as u64) as u16);
        }

        if self.count >= delta_ticks {
            self.count = self.count - delta_ticks;
        } else {
            self.count = self.reload - (delta_ticks - self.count);
        }

        self.time = time;
    }

    /*
     * Transition channel state upon new data port write
     */
    fn next_state(&mut self) {
        match self.state {
            PITChannelState::Initial => {
                panic!("PIT: Bad channel state");
            },

            PITChannelState::WaitLo => {
                match self.access {
                    PITChannelAccess::LoByte =>
                        self.state = PITChannelState::Enabled,
                    PITChannelAccess::Word =>
                        self.state = PITChannelState::WaitHi,
                    _ =>
                        panic!("PIT: Invalid state"),
                }
            },

            PITChannelState::WaitHi => {
                match self.access {
                    PITChannelAccess::HiByte | PITChannelAccess::Word =>
                        self.state = PITChannelState::Enabled,
                    _ =>
                        panic!("PIT: Invalid state"),
                }
            },

            PITChannelState::Enabled => {
                match self.access {
                    PITChannelAccess::HiByte =>
                        self.state = PITChannelState::WaitHi,
                    _ =>
                        self.state = PITChannelState::WaitLo,
                }
            },
        }

        // When state changes to enabled, update count and time
        if self.state == PITChannelState::Enabled {
            self.count = self.reload;
            self.time = time::now().to_timespec();
        }
    }

    /*
     * Store current count value to internal register
     */
    fn latch_count(&mut self) {
        self.latch = self.count;
        self.read_latch = true;
    }

    /*
     * Write a byte to channel data port.
     * Will change channel state.
     */
    fn write(&mut self, val: u8) {
        // If channel was enabled, put it into one of the wait states first
        // This means that channel state will be changed twice for this write
        if self.state == PITChannelState::Enabled {
            self.next_state();
        }

        // Write portion of reload value
        match self.state {
            PITChannelState::WaitLo =>
                self.reload = (self.reload & 0xFF00) | (val as u16),
            PITChannelState::WaitHi =>
                self.reload = (self.reload & 0x00FF) | ((val as u16) << 8),
            _ =>
                panic!("PIT: Bad channel state on write"),
        }

        // Select next channel state
        self.next_state();
    }

    /*
     * Read a byte from channel data port
     */
    fn read(&mut self) -> u8 {
        // TODO: do write states have any effect on read states?
        //       i.e. if channel is waiting for reload value
        //       what happend if we write to it?

        if !self.read_more {
            if self.read_latch {
                self.read_more = true;
                return self.latch as u8;
            } else {
                match self.access {
                    PITChannelAccess::LoByte =>
                        return self.count as u8,
                    PITChannelAccess::HiByte =>
                        return (self.count >> 8) as u8,
                    PITChannelAccess::Word => {
                        self.read_more = true;
                        return self.count as u8;
                    },
                }
            }
        } else {
            self.read_more = false;
            if self.read_latch {
                self.read_latch = false;
                return (self.latch >> 8) as u8;
            } else {
                assert!(self.access == PITChannelAccess::Word);
                return (self.count >> 8) as u8;
            }
        }
    }
}

#[cfg(test)]
mod pit_channel_test
{
    use super::{PITChannel, PITChannelMode, PITChannelAccess, PITChannelState};
    use time;

    /*
     * A helper to read latched count from pit channel
     */
    fn read_count(ch: &mut PITChannel) -> u16 {
        ch.latch_count();
        let lo = ch.read();
        let hi = ch.read();
        return (lo as u16) | ((hi as u16) << 8);
    }

    /*
     * A helper to calculate pit channel effective frequency
     */
    fn calc_frequency(ch: &mut PITChannel) -> f64 {
        // Set reload value
        ch.write(0xFF);
        ch.write(0xFF);

        ch.update();
        let c1 = read_count(ch);
        let t1 = ch.time;

        ch.update();
        let c2 = read_count(ch);
        let t2 = ch.time;

        println!("{}, {}", c1, c2);

        let mut cd = 0;
        if c2 > c1 {
            cd = 0x10000 - c2 + c1;
        } else {
            cd = c1 - c2;
        }

        let td = t2 - t1;

        println!("{}, {}", cd, td.num_microseconds().unwrap());
        return (cd as f64) / (td.num_microseconds().unwrap() as f64);
    }

    /*
     * Test reset state
     */
    #[test] fn reset() {
        let mut ch = PITChannel::default();

        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        assert!(ch.reload == 0);
        assert!(ch.count == 0);

        // Update does not change count until reload value is set
        ch.update();
        assert!(read_count(&mut ch) == 0);
        ch.write(0xFF);
        ch.write(0xFF);
        ch.update();
        assert!(read_count(&mut ch) != 0);
    }

    /*
     * Test various reload value combination
     */
    #[test] fn reload_value() {
        let mut ch = PITChannel::default();

        // Word
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        assert!(ch.state == PITChannelState::WaitLo);
        ch.write(0xAB);
        assert!(ch.state == PITChannelState::WaitHi);
        ch.write(0xCD);
        assert!(ch.state == PITChannelState::Enabled);
        assert!(ch.reload == 0xCDAB);

        // LoByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::LoByte);
        assert!(ch.state == PITChannelState::WaitLo);
        ch.write(0xAB);
        assert!(ch.state == PITChannelState::Enabled);
        assert!(ch.reload == 0xAB);

        // HiByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::HiByte);
        assert!(ch.state == PITChannelState::WaitHi);
        ch.write(0xCD);
        assert!(ch.state == PITChannelState::Enabled);
        assert!(ch.reload == 0xCD00);
    }

    /*
     * Test read from channel data port.
     */
    #[test] fn read() {
        let mut ch = PITChannel::default();

        // Word
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        ch.write(0xFF);
        ch.write(0xFF);
        ch.update(); // To move ticks forward a bit
        assert!(ch.read() == (ch.count & 0xFF) as u8);
        assert!(ch.read() == ((ch.count >> 8) & 0xFF) as u8);

        // LoByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::LoByte);
        ch.write(0xFF);
        ch.update(); // To move ticks forward a bit
        assert!(ch.read() == (ch.count & 0xFF) as u8);
        assert!(ch.read() == (ch.count & 0xFF) as u8); // Value is repeated

        // HiByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::HiByte);
        ch.write(0xFF);
        ch.update(); // To move ticks forward a bit
        assert!(ch.read() == ((ch.count >> 8) & 0xFF) as u8);
        assert!(ch.read() == ((ch.count >> 8) & 0xFF) as u8); // Value is repeated
    }

    /*
     * Test latched read from channel data port.
     */
    #[test] fn read_latched() {
        let mut ch = PITChannel::default();

        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        ch.write(0xFF);
        ch.write(0xFF);

        // Read from count pre-latch
        ch.update();
        let count1 = (ch.read() as u16) | ((ch.read() as u16) << 8);
        assert!(count1 == ch.count);

        ch.latch_count();
        ch.update(); // Move ticks again so that latched value differs from count

        // Read from latch
        let latch = (ch.read() as u16) | ((ch.read() as u16) << 8);
        assert!(latch == ch.latch);
        assert!(latch == count1);

        // Read from count
        let count2 = (ch.read() as u16) | ((ch.read() as u16) << 8);
        assert!(count2 == ch.count);
        assert!(latch != count2);
    }

    /*
     * Test PIT mode 0
     */
    #[test] fn mode0() {
        let mut ch = PITChannel::default();

        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        assert!(ch.access == PITChannelAccess::Word);
        assert!(ch.mode == PITChannelMode::Mode0);
        assert!(ch.state == PITChannelState::WaitLo);

        ch.write(0xAB);
        assert!(ch.state == PITChannelState::WaitHi);

        ch.write(0xCD);
        assert!(ch.state == PITChannelState::Enabled);
        assert!(ch.reload == 0xCDAB);

        // Count is set to reload value after reset is complete
        assert!(0xCDAB == read_count(&mut ch));

        // Count decrements until it reaches 0 and then reload value is reset again
        let mut seen_decrement = false;
        loop {
            ch.update();
            let c1 = read_count(&mut ch);

            ch.update();
            let c2 = read_count(&mut ch);

            // We should see at least one decrement before value wraps around
            if c2 < c1 {
                seen_decrement = true;
            } else {
                assert!(seen_decrement);
                break;
            }
        }

        // Check freqency
        let freq = calc_frequency(&mut ch);
        println!("{}", freq);
    }
}

enum PITState
{
    Initial,            // Initial state, waiting to be programmed
    ChannelSelected,    // Channel is selected and reset, waiting on reload value
    ReadBack,           // Read back command is sent, TODO
    ReloadSet,
}

impl PITState {
    fn default() -> PITState {
        PITState::Initial
    }
}

struct PIT
{
    channels: [PITChannel; 3],
    state: PITState,
    cur_channel: u8,            // Currently selected channel
}

impl PIT
{
    // Creates new PIT instance
    fn new() -> PIT {
        PIT {
            channels: [PITChannel::default(); 3],
            state: PITState::default(),
            cur_channel: 0,
        }
    }

    /*
     * Get current channels counter value
     */
    fn get_counter(&self, chan: u8) -> u16 {
        assert!(chan <= 3);
        return self.channels[chan as usize].count;
    }

    /*
     * Write to mode/command register
     */
    fn write_mode(&mut self, val: u8) {
        let cmd = PITModeReg::from(val);

        // TODO: readback
        if cmd.select == PIT_SELECT_READBACK {
            unimplemented!();
        }

        // TODO: bcd
        if cmd.is_bcd {
            unimplemented!();
        }

        let chan = cmd.select as usize;

        if cmd.access == PIT_ACCESS_LATCH_COUNT {
            self.channels[chan].latch_count();
        } else {
            let access = match cmd.access {
                PIT_ACCESS_LOBYTE => PITChannelAccess::LoByte,
                PIT_ACCESS_HIBYTE => PITChannelAccess::HiByte,
                PIT_ACCESS_LOBYTE_HIBYTE => PITChannelAccess::Word,
                _ => panic!(),
            };

            let mode = match cmd.mode {
                PIT_MODE_0 => PITChannelMode::Mode0,
                PIT_MODE_1 => PITChannelMode::Mode1,
                PIT_MODE_2 => PITChannelMode::Mode2,
                PIT_MODE_3 => PITChannelMode::Mode3,
                PIT_MODE_4 => PITChannelMode::Mode4,
                PIT_MODE_5 => PITChannelMode::Mode5,
                _ => panic!(),
            };

            // Select channel and reset it
            self.channels[chan].reset(mode, access);
        }
    }

    fn write_data(&mut self, chan: u8, val: u8) {
        self.channels[chan as usize].write(val);
    }
}

///////////////////////////////////////////////////////////////////////////////

struct PITDev
{
    pit: RefCell<PIT>,
}

impl vm::io_handler for PITDev
{
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType
    {
        unimplemented!();
    }


    fn io_write(&self, port: u16, data: vm::IoOperandType)
    {
        unimplemented!();
    }
}

pub fn init(vm: &mut vm::vm)
{
	let dev = Rc::new(PITDev {
        pit: RefCell::new(PIT::new()),
    });

    vm::register_io_region(vm, dev.clone(), PIT_CH0, 4);
}

