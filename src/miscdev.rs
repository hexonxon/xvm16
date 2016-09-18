/*
 * Implementation of a miscdev io handler
 * miscdev is a stub io handler that returns a fixed value when read
 */

use vm;
use std::rc::Rc;
use std::cell::RefCell;

struct miscdev 
{
    val: RefCell<vm::IoOperandType>,
}

#[allow(unused_variables)]
impl vm::io_handler for miscdev 
{

    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType 
    {
        return *self.val.borrow();
    }

    fn io_write(&self, port: u16, data: vm::IoOperandType) 
    {
        *self.val.borrow_mut() = data;
    }
}

pub fn init()
{
    let a20 = Rc::new(miscdev {
        val: RefCell::new(vm::IoOperandType::byte(0x04)), // A20 enabled
    });
    vm::register_io_region(a20, 0x92, 1);

    let fwcfg1 = Rc::new(miscdev {
        val: RefCell::new(vm::IoOperandType::word(0)),
    });
    vm::register_io_region(fwcfg1, 0x510, 2);

    let fwcfg2 = Rc::new(miscdev {
        val: RefCell::new(vm::IoOperandType::byte(0)),
    });
    vm::register_io_region(fwcfg2, 0x511, 1);

    let dma = Rc::new(miscdev {
        val: RefCell::new(vm::IoOperandType::byte(0)),
    });
    vm::register_io_region(dma.clone(), 0xd, 1);
    vm::register_io_region(dma.clone(), 0xda, 1);
    vm::register_io_region(dma.clone(), 0xd6, 1);
    vm::register_io_region(dma.clone(), 0xd4, 1);
}

