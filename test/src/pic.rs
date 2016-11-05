/*
 * 8259A PIC interface
 *
 * TODO: some code here is common with PIC implementation in xvm
 *       make some common definition crate if possible
 */

use arch;
use pio::{inb, outb};

const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

const PIC_READ_IRR: u8 = 0x0A;
const PIC_READ_ISR: u8 = 0x0B;
const PIC_EOI: u8 = 0x20;

static mut OFFSETS: u16 = 0xFFFF;

pub fn slave_arg(val: u16) -> u8 {
    (val >> 8) as u8
}

pub fn master_arg(val: u16) -> u8 {
    val as u8
}

pub fn make_arg(master: u8, slave: u8) -> u16 {
    master as u16 | ((slave as u16) << 8)
}

/**
 * Reset PIC to new vector bases and interrupts masks
 *
 * \offset  Vector offsets for master (LSB) and slave (MSB)
 * \mask    Interrupt masks for master (LSB) and slave (MSB)
 */
pub fn reset(offset: u16, mask: u16)
{
    let iscope = arch::InterruptGuard::default();

    unsafe {
        // ICW1
        outb(PIC_MASTER_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC_SLAVE_CMD, ICW1_INIT | ICW1_ICW4);

        // ICW2 (vector offsets)
        outb(PIC_MASTER_DATA, master_arg(offset));
        outb(PIC_SLAVE_DATA, slave_arg(offset));

        // ICW3 (cascade)
        outb(PIC_MASTER_DATA, 4);
        outb(PIC_SLAVE_DATA, 2);

        // ICW4
        outb(PIC_MASTER_DATA, ICW4_8086);
        outb(PIC_SLAVE_DATA, ICW4_8086);

        // Masks
        set_mask(mask);
        OFFSETS = offset;
    }
}

pub fn mask() -> u16
{
    unsafe {
        make_arg(inb(PIC_MASTER_DATA), inb(PIC_SLAVE_DATA))
    }
}

pub fn set_mask(mask: u16)
{
    unsafe {
        outb(PIC_MASTER_DATA, master_arg(mask));
        outb(PIC_SLAVE_DATA, slave_arg(mask));
    }
}

pub fn set_mask2(master: u8, slave: u8)
{
    set_mask(make_arg(master, slave));
}

pub fn offset() -> u16
{
    unsafe {
        OFFSETS
    }
}

pub fn master_offset() -> u8
{
    master_arg(offset())
}

pub fn slave_offset() -> u8
{
    slave_arg(offset())
}

// TODO: move to common utils code
fn set_bit8(val: u8, bit: u8) -> u8 {
    assert!(bit < 8);
    val | (1_u8 << bit)
}

// TODO: move to common utils code
fn clear_bit8(val: u8, bit: u8) -> u8 {
    assert!(bit < 8);
    val & !(1_u8 << bit)
}

/**
 * For a given IRQ number returns interrupt vector for current PIC configuration
 */
pub fn get_interrupt_vector(irq: u8) -> u8
{
    if irq < 8 {
        master_offset() + irq
    } else if irq < 16 {
        slave_offset() + irq
    } else {
        panic!()
    }

}

/**
 * Mask or unmask and IRQ given its interrupt vector
 */
pub fn mask_vector(vec: u8, is_masked: bool)
{
    let mask = mask();
    let mut master = master_arg(mask);
    let mut slave = slave_arg(mask);
        
    if vec >= master_offset() && vec < (master_offset() + 8) {
        if is_masked {
            master = set_bit8(master, vec - master_offset());
        } else {
            master = clear_bit8(master, vec - master_offset());
        }
    } else if vec >= slave_offset() && vec < (slave_offset() + 8) {
        if is_masked {
            slave = set_bit8(slave, vec - master_offset());
        } else {
            slave = clear_bit8(slave, vec - master_offset());
        }
    }

    set_mask2(master, slave);
}

/**
 * Send end-of-interrupt for IRQ
 */
pub fn EOI(irq: u8)
{
    unsafe {
        if irq >= 8 {
            outb(PIC_SLAVE_CMD, PIC_EOI);
        }
        outb(PIC_MASTER_CMD, PIC_EOI);
    }
}

/**
 * Read ISR registers
 */
pub fn ISR() -> u16
{
    unsafe {
        outb(PIC_MASTER_CMD, PIC_READ_ISR);
        outb(PIC_SLAVE_CMD, PIC_READ_ISR);
        make_arg(inb(PIC_MASTER_CMD), inb(PIC_SLAVE_CMD))
    }
}

/**
 * Read IRR registers
 */
pub fn IRR() -> u16
{
    unsafe {
        outb(PIC_MASTER_CMD, PIC_READ_IRR);
        outb(PIC_SLAVE_CMD, PIC_READ_IRR);
        make_arg(inb(PIC_MASTER_CMD), inb(PIC_SLAVE_CMD))
    }
}
