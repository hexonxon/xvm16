
use vm;

struct qemudbg_dev {}

impl vm::io_handler_ops for qemudbg_dev {
    fn io_read(&self, port: u16, size: u8) -> vm::IoOperandType {
        assert!(size == 1);
        assert!(port == 0x402);
        unimplemented!();
    }

    fn io_write(&self, addr: u16, data: vm::IoOperandType) {
        assert!(addr == 0x402);

        // Output to debug console
        print!("{}", data.unwrap_byte() as char);
    }
}

static QEMUDBG: qemudbg_dev = qemudbg_dev{};

pub fn init(vm: &mut vm::vm) {
    vm::register_io_handler(vm, &QEMUDBG, 0x402, 1);
}
