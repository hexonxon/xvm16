/*
 * Simple bitmap implementation.
 * TODO: Switch to BitVec once it is in stable
 */

use std::mem;
use std::ptr;

pub struct Bitmap
{
    bits: usize, /* capacity in bits */
    size: usize, /* allocated size in bytes */
    data: Vec<u8>,
}

impl Bitmap
{
    pub fn new(bits: usize) -> Bitmap {
        assert!(bits > 0);

        let size = (bits + 7) >> 3;
        assert!((size << 3) >= bits);

        let mut data = Vec::new();
        data.resize(size, 0);

        Bitmap {
            bits: bits,
            size: size,
            data: data,
        }
    }

    pub fn is_set(&self, bit: usize) -> bool {
        assert!(bit < self.bits);

        let byte = self.data[bit >> 3];
        let mask = 1u8 << (bit & 0x7);
        return (byte & mask) != 0;
    }

    pub fn set(&mut self, bit: usize) {
        assert!(bit < self.bits);

        let mask = 1u8 << (bit & 0x7);
        self.data[bit >> 3] |= mask;
    }

    pub fn clear(&mut self, bit: usize) {
        assert!(bit < self.bits);

        let mask = 1u8 << (bit & 0x7);
        self.data[bit >> 3] &= !mask;
    }

    pub fn clear_all(&mut self) {
        unsafe {
            ptr::write_bytes(self.data.as_mut_ptr(), 0, self.size);
        }
    }

    fn bsf32(val: u32) -> usize {
        assert!(val != 0);

        /* TODO: Inline assembly is unstable so use dumb manual approach */
        /*
           let mut bit: u32 = 0;
           asm!("bsf $1, %0"
           : "=r"(bit)
           : "r"(val)
           );

           return bit;
        */

        let mut val = val;
        let mut bit = 0;
        for i in 0..32 {
            if (val & 0x1) != 0 {
                return bit;
            }

            val >>= 1;
            bit += 1;
        }

        return 0;
    }

    /**
     * Return first set bit index or None
     */
    pub fn bsf(&self) -> Option<usize> {
        let p: *const u32 = self.data.as_ptr() as *const u32;

        let words = self.size / mem::size_of::<u32>();
        let rem = self.size - words * mem::size_of::<u32>();

        unsafe {
            for i in 0..words {
                let word = *p.offset(i as isize);
                if word == 0 {
                    continue;
                }

                return Option::Some(i * mem::size_of::<u32>() * 8 + Bitmap::bsf32(word));
            }

            if rem != 0 {
                let mut word: u32 = 0;
                ptr::copy_nonoverlapping(p.offset(words as isize) as *const u8, mem::transmute(&mut word), rem);

                if word != 0 {
                    return Option::Some(words * mem::size_of::<u32>() + Bitmap::bsf32(word));
                }
            }
        }

        return Option::None;
    }

}


#[test] 
fn bitmap_test() {
    let bits = 10;
    let mut map = Bitmap::new(bits);
    assert!(map.bits == bits);

    // Initial bits are not set
    for i in 0..bits {
        assert!(!map.is_set(i));
    }

    // Gradually set all bits and verify
    for i in 0..bits {
        map.set(i);
        assert!(map.is_set(i));
        for j in (i + 1)..bits {
            assert!(!map.is_set(j));
        }
    }

    // Clear a bit and check again
    map.clear(bits >> 1);
    for i in 0..bits {
        if i == (bits >> 1) {
            assert!(!map.is_set(i));
        } else {
            assert!(map.is_set(i));
        }
    }
}

#[test]
fn bitmap_bsf_test() {
    let bits = 100;
    let mut map = Bitmap::new(bits);

    assert!(map.bsf().is_none());

    map.set(42);
    assert!(map.is_set(42));

    let res = map.bsf();
    assert!(res.is_some() && res.unwrap() == 42);
}

#[test]
fn bitmap_clear_all_test() {
    let bits = 100;
    let mut map = Bitmap::new(bits);

    for i in 0..bits {
        map.set(i);
        assert!(map.is_set(i));
    }

    map.clear_all();
    for i in 0..bits {
        assert!(!map.is_set(i));
    }
}
