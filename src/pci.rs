/*
 * PCI root emulation
 */

use vm;

use std::rc::Rc;
use std::cell::RefCell;

const PCI_CONFIG_ADDRESS:u16    = 0xCF8;
const PCI_CONFIG_DATA:u16       = 0xCFC;

struct PCIRoot
{
}

impl PCIRoot 
{
    fn new() -> PCIRoot {
        PCIRoot {}
    }

    fn read32(&mut self, port: u16) -> u32 {
        0xFFFFFFFF
    }

    fn write32(&mut self, port: u16, data: u32) {
        /* STUB */
    }
}

///////////////////////////////////////////////////////////////////////////////

struct PCIRootDev
{
    pci_root: RefCell<PCIRoot>,
}

impl vm::io_handler for PCIRootDev
{
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType
    {
        let mut dev = self.pci_root.borrow_mut();
        let dword = dev.read32(port);

        match size {
            1 => vm::IoOperandType::byte((dword & 0xFF) as u8),
            2 => vm::IoOperandType::word((dword & 0xFFFF) as u16),
            4 => vm::IoOperandType::dword(dword),
            _ => panic!()
        }
    }


    fn io_write(&self, port: u16, data: vm::IoOperandType)
    {
        let mut dev = self.pci_root.borrow_mut();
        dev.write32(port, data.unwrap_dword());
    }
}

pub fn init()
{
	let dev = Rc::new(PCIRootDev {
        pci_root: RefCell::new(PCIRoot::new()),
    });

    vm::register_io_region(dev.clone(), PCI_CONFIG_ADDRESS, 4);
    vm::register_io_region(dev.clone(), PCI_CONFIG_DATA, 4);
}

