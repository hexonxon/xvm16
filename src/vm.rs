
use hypervisor_framework::*;
use std::sync::Arc;

extern "C" {
    fn valloc(size: usize) -> *mut ::std::os::raw::c_void;
}

/**
 * VM allocated memory region
 */
pub struct memory_region 
{
    pub data: hv_uvaddr_t,
    pub size: usize,
}

pub struct memory_mapping
{
    region: Arc<memory_region>,
    base: hv_gpaddr_t,
    flags: hv_memory_flags_t,
}

pub trait io_handler_ops {
    fn io_read(&self, addr: u16, size: u8, data: *mut u8);
    fn io_write(&self, addr: u16, size: u8, data: *const u8);
}

pub struct io_handler<'a>
{
    ops: &'a io_handler_ops,
    base: u16,
    size: u8,
}

/**
 * VM state 
 *
 * HV framework internally creates a single global VM context for process which means 
 * that dynamic instanses of this struct don't really make sense.
 * However, rust makes it hard to work with globals, so we will have dynamic instance.
 *
 * TODO: drop trait to clean up and call hv_vm_destroy
 * TODO: a better lookup for memory mappings
 */
pub struct vm<'a> {
    /** HV vcpu id */
    pub vcpu: hv_vcpuid_t,

    /** Mapped memory regions, simple vector for now */
    pub memory: Vec<memory_mapping>,

    pub io: Vec<io_handler<'a>>, 
}

pub fn alloc_pages(size: usize) -> hv_uvaddr_t 
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

pub fn create() -> vm<'static>
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

pub fn register_io_handler<'a>(vm: &mut vm<'a>, handler: &'a io_handler_ops, base: u16, len: u8)
{
    // TODO: check of range intersects
    vm.io.push(io_handler { ops: handler, base: base, size: len });
}
