use num::traits::*;

#[derive(Copy, Clone)]
pub struct AddressRange<T: PrimInt> {
	pub base: T,
	pub size: T,
}

pub type MemoryRange = AddressRange<u64>;
pub type IoRange = AddressRange<u16>;

pub fn IsEmptyRange<T: PrimInt> (x: &AddressRange<T>) -> bool 
{
	x.size == T::zero()
}

pub fn IsIntersectingRanges<T: PrimInt> (x: &AddressRange<T>, y: &AddressRange<T>) -> bool
{
	let y_len = y.base + y.size;
	let x_len = x.base + x.size;

	(x.base >= y.base && x.base < y_len) || (y.base >= x.base && y.base < x_len)
}

#[test]
fn TestRanges() 
{
	let x = MemoryRange { base: 0, size: 10 };
	let y = MemoryRange { base: 5, size: 2 };
	let z = MemoryRange { base: 10, size: 2};
	let o = MemoryRange { base: 0, size: 0 };

	assert!(IsIntersectingRanges(&x, &y));
	assert!(IsIntersectingRanges(&y, &x));
	assert!(!IsIntersectingRanges(&x, &z));
	assert!(!IsIntersectingRanges(&z, &x));

	assert!(IsEmptyRange(&o));
	assert!(IsIntersectingRanges(&x, &o));
	assert!(!IsIntersectingRanges(&y, &o));
}
