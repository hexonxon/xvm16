
use vm;

struct qemudbg {}

impl vm::io_handler_ops for qemudbg {
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType {
        assert!(size == 1);
        assert!(port == 0x402);
        unimplemented!();
    }

    fn io_write(&mut self, addr: u16, data: vm::IoOperandType) {
        assert!(addr == 0x402);

        // Output to debug console
        print!("{}", data.unwrap_byte() as char);
    }
}

pub fn init(vm: &mut vm::vm) {
    let dev = Box::new(qemudbg {});
    vm::register_io_handler(vm, dev, 0x402, 1);
}
