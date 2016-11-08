/*
 * VM model
 *
 * TODO: describe locking policy
 */

use std::sync::{Arc, Mutex, atomic};
use std::rc::Rc;
use std::mem;
use rlibc::*;
use hypervisor_framework::*;
use util::bitmap::*;
use event;

extern "C" {
    fn valloc(size: usize) -> *mut ::std::os::raw::c_void;
}

/**
 * VM allocated memory region
 *
 * Describes single contigious region of host memory allocated to VM
 * A region can be mapped to guest physical memory, several mappings of the same region can exist
 * (see memory_mapping)
 */
pub struct memory_region {
    pub data: hv_uvaddr_t,  // Host base address
    pub size: usize,        // Region size in bytes
}

impl memory_region {

    /**
     * Read bytes from guest region into caller buffer
     */
    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> usize {
        if offset >= self.size {
            return 0;
        }

        let toread = if offset + buf.len() > self.size {
            self.size - offset
        } else {
            buf.len()
        };

        unsafe {
            memcpy(buf.as_mut_ptr(), (self.data as *const u8).offset(offset as isize), toread);
        }

        toread
    }

    /**
     * Write bytes from caller buffer to guest memory region
     */
    pub fn write_bytes(&self, offset: usize, buf: &[u8]) -> usize {
        if offset >= self.size {
            return 0;
        }

        let towrite = if offset + buf.len() > self.size {
            self.size - offset
        } else {
            buf.len()
        };

        unsafe {
            memcpy((self.data as *mut u8).offset(offset as isize), buf.as_ptr(), towrite);
        }

        towrite
    }
}

/**
 * Guest memory mapping
 * Describes a mapping of memory_region to specific guest physical address
 */
pub struct memory_mapping
{
    pub region: Arc<memory_region>,     // Mapped memory region
    pub base: hv_gpaddr_t,              // Guest base physical address
    pub flags: hv_memory_flags_t,       // Mapping flags (RWX)
}

/**
 * IO handler trait
 * Instances of this trait register as guest PIO handlers for specific io regions
 */
pub trait io_handler
{
    /**
     * Read from IO port
     */
    fn io_read(&self, addr: u16, size: u8) -> IoOperandType;

    /**
     * Write to IO port
     */
    fn io_write(&self, addr: u16, data: IoOperandType);
}

/**
 * Guest IO address space region
 * Usually registered by emulated devices to handle guest IO requests
 */
pub struct io_region
{
    base: u16,              // IO port base
    size: u8,               // IO size (1, 2, 4)
    ops: Rc<io_handler>,    // Instance of io_handler for this region
}

/**
 * Interrupt controller trait
 *
 * Instances of this trait provide generic VM with an interface to assert IRQ lines and
 * acknowledge delivered interrupts.
 */
pub trait interrupt_controller
{
    /**
     * Assert given IRQ line.
     * \param irq   IRQ line to assert
     */
    fn assert_irq(&self, irq: u8);

    /**
     * Notify interrupt controller that interrupt vector has been injected in guest
     * \param vec   Interrupt vector that was previously raise with raise_external_interrupt
     */
    fn ack(&self, vec: u8);
}

/**
 * VM internal state for owning process
 *
 * HV framework internally creates a single global VM context for running process.
 * This means that there is a single shared VM state per single process.
 *
 * TODO: drop trait to clean up and call hv_vm_destroy
 * TODO: a better lookup for memory mappings
 */
struct vm {
    /* HV vcpu id */
    vcpu: hv_vcpuid_t,

    /* Interrupt state */
    pic: Option<Rc<interrupt_controller>>,
    pending_ext_ints: Bitmap,

    /* Mapped memory regions */
    memory: Vec<memory_mapping>,

    /* Registred PIO regions */
    io: Vec<io_region>,
}

/*
 * Unsafe heap pointer to global VM state
 *
 * HV framework internally creates a single global VM context for process context which means 
 * that dynamic instanses of this struct don't really make sense.
 *
 * Use get_vm() to safely unwrap this pointer.
 *
 * TODO: We are single threaded now, but remeber to add proper sync in case of multiple threads
 */
static mut VM: Option<*mut vm> = Option::None;

fn get_vm() -> &'static mut vm
{
    unsafe {
        mem::transmute(VM.unwrap())
    }
}

fn get_pic() -> Rc<interrupt_controller>
{
    get_vm().pic.clone().unwrap()
}

pub fn create()
{
    unsafe {
        let res = hv_vm_create(HV_VM_DEFAULT);
        assert!(res == HV_SUCCESS);

        let vm = vm {
                    vcpu: vcpu_create(),
                    pic: Option::None,
                    pending_ext_ints: Bitmap::new(256),
                    memory: Vec::new(),
                    io: Vec::new()
        };

        VM = Option::Some(mem::transmute(Box::new(vm)));
    }
}

pub fn register_interrupt_controller(pic: Rc<interrupt_controller>)
{
    get_vm().pic = Option::Some(pic);
}

pub fn assert_irq(vec: u8)
{
    get_pic().assert_irq(vec);
}

pub fn has_pending_interrupts() -> bool
{
    get_vm().pending_ext_ints.has_any_set()
}

pub fn raise_external_interrupt(vec: u8)
{
    get_vm().pending_ext_ints.set(vec as usize);
}

pub fn cancel_all_external_interrupts()
{
    get_vm().pending_ext_ints.clear_all();
}

pub fn next_external_interrupt() -> Option<u8>
{
    match get_vm().pending_ext_ints.bsf() {
        Some(vec) => {
            /* ACK interrupt */
            get_vm().pending_ext_ints.clear(vec);
            get_pic().ack(vec as u8);
            return Option::Some(vec as u8);
        }

        None => Option::None,
    }
}

pub fn interrupt_guest()
{
    unsafe {
        let mut vcpus: [hv_vcpuid_t; 1] = [vcpu(); 1];
        let res = hv_vcpu_interrupt(vcpus.as_mut_ptr(), vcpus.len() as u32);
        if res != 0 {
            panic!("hv_vcpu_interrupt failed with {:x}", res);
        }
    }
}

pub fn get_guest_exec_time() -> u64
{
    unsafe {
        let mut time: u64 = 0;
        let res = hv_vcpu_get_exec_time(vcpu(), &mut time as *mut u64);
        if res != 0 {
            panic!("hv_vcpu_get_exec_time failed with {:x}", res);
        }

        time
    }
}

fn alloc_pages(size: usize) -> hv_uvaddr_t 
{
    unsafe {
        let va = valloc(size);
        assert!(!va.is_null());
        return va;
    }
}

pub fn vcpu() -> hv_vcpuid_t
{
    get_vm().vcpu
}

pub fn alloc_memory_region(size: usize) -> Arc<memory_region>
{
    let va = alloc_pages(size);
    Arc::new(memory_region { size: size, data: va })
}

pub fn map_memory_region(base: hv_gpaddr_t, flags: hv_memory_flags_t, region: Arc<memory_region>)
{
    unsafe {
        let res = hv_vm_map(region.data, base, region.size, flags);
        assert!(res == HV_SUCCESS);
    }

    get_vm().memory.push(memory_mapping { region: region, base: base, flags: flags });
}

pub fn find_memory_mapping(addr: hv_gpaddr_t) -> Option<&'static memory_mapping>
{
    for i in &get_vm().memory {
        if addr >= i.base && addr < i.base + i.region.size as u64 {
            return Some(i);
        }
    }

    return None;
}

pub fn read_guest_memory(addr: hv_gpaddr_t, buf: &mut [u8]) -> usize
{
    let mapping = match find_memory_mapping(addr) {
        Some(mapping) => mapping,
        None => return 0,
    };

    assert!(addr >= mapping.base);
    mapping.region.read_bytes((addr - mapping.base) as usize, buf)
}

pub fn vcpu_create() -> hv_vcpuid_t 
{
    unsafe {
        let mut vcpu: hv_vcpuid_t = 0;  
        let res = hv_vcpu_create(&mut vcpu, HV_VCPU_DEFAULT);
        assert!(res == HV_SUCCESS);
        vcpu
    }
}

pub fn run() -> hv_return_t
{
    let res: hv_return_t;

    /* Enable event loop before returning to guest */
    event::unlock_event_loop();

    /* Run guest vcpu */
    unsafe {
        res = hv_vcpu_run(vcpu())
    }

    /* Disable event loop after returning to guest */
    event::lock_event_loop();
    return res;
}

pub fn register_io_region(handler: Rc<io_handler>, base: u16, len: u8)
{
    // TODO: check if range intersects
    get_vm().io.push(io_region {
        ops: handler,
        base: base,
        size: len
    });
}

#[derive(Clone, Copy)]
pub enum IoOperandType {
    byte(u8),
    word(u16),
    dword(u32),
}

#[allow(dead_code)]
impl IoOperandType {
    pub fn unwrap_byte(&self) -> u8 {
        match self {
            &IoOperandType::byte(v) => v,
            _ => panic!(),
        }
    }

    pub fn unwrap_word(&self) -> u16 {
        match self {
            &IoOperandType::word(v) => v,
            _ => panic!(),
        }
    }

    pub fn unwrap_dword(&self) -> u32 {
        match self {
            &IoOperandType::dword(v) => v,
            _ => panic!(),
        }
    }

    pub fn make_unhandled(size: u8) -> IoOperandType {
        match size {
            1 => IoOperandType::byte(0xFF),
            2 => IoOperandType::word(0xFFFF),
            4 => IoOperandType::dword(0xFFFFFFFF),
            _ => panic!(),
        }
    }
}

pub fn handle_io_read(port: u16, size: u8) -> IoOperandType
{
    for i in &get_vm().io {
        if port == i.base {
            return i.ops.io_read(port, size);
        }
    }

    panic!("Unhandled IO read from port {:x}", port);
}

pub fn handle_io_write(port: u16, data: IoOperandType)
{
    for i in &get_vm().io {
        if port == i.base {
            i.ops.io_write(port, data);
            return;

        }
    }

    panic!("Unhandled IO write to port {:x}", port);
}
