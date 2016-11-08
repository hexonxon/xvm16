/*
 * PIT emulation
 */

use vm;

use std::rc::Rc;
use std::cell::RefCell;
use time;
use event;

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
const PIT_BCD_MODE: u8 = 0b1;
const PIT_BINARY_MODE: u8 = 0b0;

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
    latch_locked: bool,     // Latch is locked and should not be updated
    gate_state: bool,
    out_state: bool,
    mode: PITChannelMode,
    state: PITChannelState,
    access: PITChannelAccess,
    read_more: bool,        // There is 1 more byte to read
    first_update: bool,     // Have we seen an update since last reload?
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
            latch_locked: false,
            gate_state: false,
            out_state: false,
            read_more: false,
            first_update: false,
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
        self.latch_locked = false;
        self.gate_state = false;
    }

    fn set_count(&mut self, val: u16) {
        self.count = val;
        if !self.latch_locked {
            self.latch = self.count;
        }
    }

    fn event_handler(ev: event::Event) {
        vm::assert_irq(0);
        vm::interrupt_guest();
    }

    /*
     * Mode specific handling of new reload value
     */
    fn reload(&mut self) {
        match self.mode {
            PITChannelMode::Mode0 => {
                self.first_update = true;
                self.out_state = false;
            },

            _ => {
                panic!();
            }
        };

        let count = self.reload;
        self.set_count(count);

        /* Delay in microseconds */
        let delay = count as u64 * 1000000 / PIT_FREQ_HZ;

        let ev = event::create_event(PITChannel::event_handler);
        event::schedule_event(delay, ev);
    }

    /*
     * Update stored value based on operation mode and elapsed ticks
     */
    fn update(&mut self, ticks: u64) {
        if self.state != PITChannelState::Enabled {
            return;
        }

        match self.mode {
            PITChannelMode::Mode0 => {
                // Account for one clock tick spent on reloading counter value right after reload
                let mut ticks = ticks;
                if self.first_update {
                    ticks -= 1;
                    self.first_update = false;
                }

                // When reaching 0 set out to high and to remain high until next reload value
                if ticks >= self.count as u64 {
                    self.set_count(0);
                    self.out_state = true;
                } else {
                    let count = self.count - ticks as u16;
                    self.set_count(count);
                }
            },

            _ => {
                panic!();
            }
        };
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
        // TODO: Mode specific on what to do after reload is set - refactor
        if self.state == PITChannelState::Enabled {
            self.reload();
        }
    }

    fn gate_set(&mut self, state: bool) {
        self.gate_state = state;
    }

    fn out(&self) -> bool {
        self.out_state
    }

    /*
     * Store current count value to internal register
     */
    fn latch_count(&mut self) {
        self.latch_locked = true;
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

        let mut res = 0;

        if self.read_more {
            assert!(self.access == PITChannelAccess::Word);
            self.read_more = false;
            res = (self.latch >> 8) as u8;
        } else {
            res = match self.access {
                PITChannelAccess::LoByte =>
                    self.latch as u8,
                PITChannelAccess::HiByte =>
                    (self.latch >> 8) as u8,
                PITChannelAccess::Word => {
                    self.read_more = true;
                    self.latch as u8
                },
            };
        }

        // Latch is always unlocked when full read is complete
        if !self.read_more {
            self.latch_locked = false;
        }

        return res;
    }
}

#[cfg(test)]
mod pit_channel_test
{
    use super::{PITChannel, PITChannelMode, PITChannelAccess, PITChannelState};
    use time;

    fn read_count(ch: &mut PITChannel) -> u16 {
        let lo = ch.read();
        let hi = ch.read();
        return (lo as u16) | ((hi as u16) << 8);
    }

    fn read_latched_count(ch: &mut PITChannel) -> u16 {
        ch.latch_count();
        read_count(ch)
    }

/*
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
     * Wait for a given count value to be seen on pit channel.
     */
    fn wait_for(ch: &mut PITChannel, val: u16) {
        let mut prev = read_count(ch);
        loop {
            ch.update();
            let now = read_count(ch);

            if prev >= val {
                if now > prev || now <= val {
                    break;
                }
            }

            prev = now;
        }
    }
*/
    /*
     * Test reset state
     */
    #[test] fn reset() {
        let mut ch = PITChannel::default();

        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        assert!(ch.reload == 0);
        assert!(ch.count == 0);

        // Update does not change count until reload value is set
        ch.update(100);
        assert!(read_count(&mut ch) == 0);
        ch.write(0xFF);
        ch.write(0xFF);
        ch.update(100);
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
        ch.update(100); // To move ticks forward a bit
        assert!(ch.read() == (ch.count & 0xFF) as u8);
        assert!(ch.read() == ((ch.count >> 8) & 0xFF) as u8);

        // LoByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::LoByte);
        ch.write(0xFF);
        ch.update(100); // To move ticks forward a bit
        assert!(ch.read() == (ch.count & 0xFF) as u8);
        assert!(ch.read() == (ch.count & 0xFF) as u8); // Value is repeated

        // HiByte
        ch.reset(PITChannelMode::Mode0, PITChannelAccess::HiByte);
        ch.write(0xFF);
        ch.update(100); // To move ticks forward a bit
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
        ch.update(100);
        let count1 = read_count(&mut ch);

        ch.latch_count();
        ch.update(100); // Move ticks again so that latched value differs from count

        // Read from latch
        let latch = read_count(&mut ch);
        assert!(latch == count1);

        // After reading latch is always unlocked, update count to verify
        ch.update(100);
        let count2 = read_count(&mut ch);
        assert!(latch != count2);
    }

    /*
     * Test PIT mode 0
     */
    #[test] fn mode0() {
        let reload = 0x1000;
        let mut ch = PITChannel::default();

        ch.reset(PITChannelMode::Mode0, PITChannelAccess::Word);
        ch.write(reload as u8);
        ch.write((reload >> 8) as u8);
        assert!(read_count(&mut ch) == reload);

        // Initial output is low
        assert!(ch.out() == false);

        // reload + 1 ticks is required for mode0 output to go high, verify that
        ch.update(reload as u64);
        assert!(ch.out() == false);
        ch.update(1);
        assert!(ch.out() == true);

        // After decrementing to 0 out is high and remains high
        ch.update(100);
        assert!(ch.out() == true);

        // After writing new reload value out goes low
        ch.write(reload as u8);
        ch.write((reload >> 8) as u8);
        assert!(read_count(&mut ch) == reload);
        assert!(ch.out() == false);
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

    fn read_data(&mut self, chan: u8) -> u8 {
        self.channels[chan as usize].read()
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
        let mut dev = self.pit.borrow_mut();

        vm::IoOperandType::byte(
            match port {
                PIT_CMD => 0, // Read from CMD is ignored
                PIT_CH0 => dev.read_data(0),
                PIT_CH1 => dev.read_data(1),
                PIT_CH2 => dev.read_data(2),

                _ => panic!(),
            }
        )
    }

    fn io_write(&self, port: u16, data: vm::IoOperandType)
    {
        let mut dev = self.pit.borrow_mut();
        let data8 = data.unwrap_byte();

        match port {
            PIT_CMD => dev.write_mode(data8),
            PIT_CH0 => dev.write_data(0, data8),
            PIT_CH1 => dev.write_data(1, data8),
            PIT_CH2 => dev.write_data(2, data8),

            _ => panic!(),
        }
    }
}

pub fn init()
{
	let dev = Rc::new(PITDev {
        pit: RefCell::new(PIT::new()),
    });

    vm::register_io_region(dev.clone(), PIT_CH0, 1);
    vm::register_io_region(dev.clone(), PIT_CH1, 1);
    vm::register_io_region(dev.clone(), PIT_CH2, 1);
    vm::register_io_region(dev.clone(), PIT_CMD, 1);
}
