
use hypervisor_framework::*;
use std::sync::Arc;
use rlibc::*;

extern "C" {
    fn valloc(size: usize) -> *mut ::std::os::raw::c_void;
}

/*
 * VM allocated memory region
 */
#[derive(Debug)]
pub struct memory_region 
{
    pub data: hv_uvaddr_t,
    pub size: usize,
}

impl memory_region {

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

#[derive(Debug)]
pub struct memory_mapping
{
    pub region: Arc<memory_region>,
    pub base: hv_gpaddr_t,
    pub flags: hv_memory_flags_t,
}

pub trait io_handler_ops
{
    fn io_read(&self, addr: u16, size: u8) -> IoOperandType;
    fn io_write(&mut self, addr: u16, data: IoOperandType);
}

pub struct io_handler
{
    ops: Box<io_handler_ops>,
    base: u16,
    size: u8,
}

/*
 * VM state 
 *
 * HV framework internally creates a single global VM context for process which means 
 * that dynamic instanses of this struct don't really make sense.
 * However, rust makes it hard to work with globals, so we will have dynamic instance.
 *
 * TODO: drop trait to clean up and call hv_vm_destroy
 * TODO: a better lookup for memory mappings
 */
pub struct vm {
    /* HV vcpu id */
    pub vcpu: hv_vcpuid_t,

    /* Mapped memory regions, simple vector for now */
    pub memory: Vec<memory_mapping>,

    pub io: Vec<io_handler>,
}


fn alloc_pages(size: usize) -> hv_uvaddr_t 
{
    unsafe {
        let va = valloc(size);
        assert!(!va.is_null());
        return va;
    }
}

pub fn alloc_memory_region(size: usize) -> Arc<memory_region>
{
    let va = alloc_pages(size);
    Arc::new(memory_region { size: size, data: va })
}

pub fn map_memory_region(vm: &mut vm, base: hv_gpaddr_t, flags: hv_memory_flags_t, region: Arc<memory_region>)
{
    unsafe {
        let res = hv_vm_map(region.data, base, region.size, flags);
        assert!(res == HV_SUCCESS);
    }

    vm.memory.push(memory_mapping { region: region, base: base, flags: flags });
}

pub fn find_memory_mapping<'a>(vm: &'a vm, addr: hv_gpaddr_t) -> Option<&'a memory_mapping>
{
    for i in &vm.memory {
        if addr >= i.base && addr < i.base + i.region.size as u64 {
            return Some(i);
        }
    }

    return None;
}

pub fn read_guest_memory(vm: &vm, addr: hv_gpaddr_t, buf: &mut [u8]) -> usize 
{
    let mapping = match find_memory_mapping(vm, addr) {
        Some(mapping) => mapping,
        None => return 0,
    };

    assert!(addr >= mapping.base);
    mapping.region.read_bytes((addr - mapping.base) as usize, buf)
}

pub fn create() -> vm
{
    unsafe {
        let res = hv_vm_create(HV_VM_DEFAULT);
        assert!(res == HV_SUCCESS);
    }

    vm { vcpu: vcpu_create(), memory: Vec::new(), io: Vec::new() }
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

pub fn run(vcpu: hv_vcpuid_t) -> hv_return_t
{
    unsafe {
        hv_vcpu_run(vcpu)
    }
}

pub fn register_io_handler(vm: &mut vm, handler: Box<io_handler_ops>, base: u16, len: u8)
{
    // TODO: check of range intersects
    vm.io.push(io_handler { ops: handler, base: base, size: len });
}

#[derive(Clone, Copy)]
pub enum IoOperandType {
    byte(u8),
    word(u16),
    dword(u32),
}

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

pub fn handle_io_read(vm: &vm, port: u16, size: u8) -> IoOperandType
{
    for i in &vm.io {
        if port >= i.base && port < i.base + i.size as u16 {
            return i.ops.io_read(port, size);

        }
    }

    panic!("Unhandled IO read from port {:x}", port);
    return IoOperandType::make_unhandled(size);
}

pub fn handle_io_write(vm: &mut vm, port: u16, data: IoOperandType)
{
    for i in &mut vm.io {
        if port >= i.base && port < i.base + i.size as u16 {
            i.ops.io_write(port, data);
            return;

        }
    }

    panic!("Unhandled IO write to port {:x}", port);
}
