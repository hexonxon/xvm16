/*
 * PIO handling
 */

pub unsafe fn inb(port: u16) -> u8 {
    let mut val: u8 = 0;
    asm!("in %dx, %al" : "={al}"(val) : "{dx}"(port)); 
    return val;
}

pub unsafe fn outb(port: u16, val: u8) {
    asm!("out %al, %dx" :: "{al}"(val), "{dx}"(port)); 
}
