/*
 * Implementation of a miscdev io handler
 * miscdev is a stub io handler that returns a fixed value when read
 */

use vm;

struct miscdev {
	val: vm::IoOperandType,
}

#[allow(unused_variables)]
impl vm::io_handler_ops for miscdev {

    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType {
    	self.val.clone()
    }

    fn io_write(&mut self, port: u16, data: vm::IoOperandType) {
    	self.val = data;
    }
}

pub fn init(vm: &mut vm::vm) { 
	let a20 = Box::new(miscdev {
    	val: vm::IoOperandType::byte(0x04), // A20 enabled
    });

    vm::register_io_handler(vm, a20, 0x92, 1);
}

