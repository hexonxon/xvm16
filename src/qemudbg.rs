
use vm;

struct qemudbg_dev {}

impl vm::io_handler_ops for qemudbg_dev {
    fn io_read(&self, addr: u16, size: u8, data: *mut u8) {
        // NOTHING
        assert!(addr == 0x402);
        assert!(size == 1);
        assert!(!data.is_null());       
    }

    fn io_write(&self, addr: u16, size: u8, data: *const u8) {
        assert!(addr == 0x402);
        assert!(size == 1);
        assert!(!data.is_null());       

        // Output to debug console
        // TODO: get rid of unsafe
        unsafe {
            print!("{}", *(data as *const char));
        }
    }
}

static QEMUDBG: qemudbg_dev = qemudbg_dev{};

pub fn init(vm: &mut vm::vm) {
	vm::register_io_handler(vm, &QEMUDBG, 0x402, 1);
}
