#![allow(non_snake_case)] 
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate rlibc;
extern crate num;
extern crate core;
extern crate Hypervisor_framework;

use Hypervisor_framework::*;
use rlibc::*;
use std::sync::Arc;

extern "C" {
    fn valloc(size: usize) -> *mut ::std::os::raw::c_void;
}

fn rvmcs(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_vcpu_read_vmcs(vcpu, field as u32, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
}

fn rvmcs32(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs) -> u32
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_vcpu_read_vmcs(vcpu, field as u32, &mut v);
        assert!(res == HV_SUCCESS);
        return v as u32;
    }
}

fn wvmcs(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs, v: u64) 
{
    unsafe {
        let res = hv_vmx_vcpu_write_vmcs(vcpu, field as u32, v);
        assert!(res == HV_SUCCESS);
    }
}

fn wvmcs32(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_regs, v: u32) 
{
    unsafe {
        let res = hv_vmx_vcpu_write_vmcs(vcpu, field as u32, v as u64);
        assert!(res == HV_SUCCESS);
    }
}

fn read_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vcpu_read_register(vcpu, reg, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
} 

fn write_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, v: u64)
{
    unsafe {
        let res = hv_vcpu_write_register(vcpu, reg, v);
        assert!(res == HV_SUCCESS);
    }
} 

fn read_capability(capid: hv_vmx_capability_t) -> u64
{
    unsafe {
        let mut v: u64 = 0;
        let res = hv_vmx_read_capability(capid, &mut v);
        assert!(res == HV_SUCCESS);
        return v;
    }
}

fn check_capability(capid: hv_vmx_capability_t, val: u32) -> u32 
{
    let cap: u64 = read_capability(capid);
    let cap_low: u32 = (cap & 0xFFFFFFFF) as u32;
    let cap_high: u32 = ((cap >> 32) & 0xFFFFFFFF) as u32;

    (val | cap_low) & cap_high
}

fn dump_guest_state(vcpu: hv_vcpuid_t)
{
    println!(" Guest state: ");

    let rip = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP);
    let cs_base = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE);
    let gpa = cs_base + rip;
    println!(" RIP {:x} (CS {:x}, PA {:x})", rip, cs_base, gpa);

    println!(" CR0 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0));
    println!(" CR3 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR3));
    println!(" CR4 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR4));
    println!(" EFLAGS = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RFLAGS));
    println!(" GLA = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_GUEST_LIN_ADDR));
    println!(" EXITQ = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_QUALIFIC));
}

//
// VM handling
// 

/**
 * VM allocated memory region
 */
struct vm_memory_region 
{
    data: hv_uvaddr_t,
    size: usize,
}

struct vm_memory_mapping
{
    region: Arc<vm_memory_region>,
    base: hv_gpaddr_t,
    flags: hv_memory_flags_t,
}

unsafe impl Sync for vm_memory_region { }
unsafe impl Send for vm_memory_region { }

/**
 * VM state 
 *
 * HV framework internally creates a single global VM context for process which means 
 * that dynamic instanses of this struct don't really make sense.
 * However, rust makes it hard to work with globals, so we will have dynamic instance.
 */
struct vm {
    pub vcpu: hv_vcpuid_t,
    pub memory: Vec<vm_memory_mapping>,
}

impl vm {
    fn new() -> vm {
        vm { 
            vcpu: 0, 
            memory: Vec::new(),
        }
    }
}

fn vm_valloc(size: usize) -> hv_uvaddr_t 
{
    unsafe {
        let va = valloc(size);
        assert!(!va.is_null());
        memset(va as *mut u8, 0, size);
        return va;
    }
}

fn vm_alloc_memory_region(size: usize) -> Arc<vm_memory_region>
{
    let va = vm_valloc(size);
    Arc::new(vm_memory_region { size: size, data: va })
}

fn vm_map_memory_region(vm: &mut vm, base: hv_gpaddr_t, flags: hv_memory_flags_t, region: Arc<vm_memory_region>)
{
    unsafe {
        let res = hv_vm_map(region.data, base, region.size, flags);
        assert!(res == HV_SUCCESS);
    }

    vm.memory.push(vm_memory_mapping { region: region, base: base, flags: flags });
}

fn vm_create() -> vm
{
    unsafe {
        let res = hv_vm_create(HV_VM_DEFAULT);
        assert!(res == HV_SUCCESS);
    }

    return vm::new();
}

fn vm_vcpu_create() -> hv_vcpuid_t 
{
    unsafe {
        let mut vcpu: hv_vcpuid_t = 0;  
        let res = hv_vcpu_create(&mut vcpu, HV_VCPU_DEFAULT);
        assert!(res == HV_SUCCESS);
        vcpu
    }
}

fn vm_run(vcpu: hv_vcpuid_t) -> hv_return_t
{
    unsafe {
        hv_vcpu_run(vcpu)
    }
}

fn main() 
{
    // Init VM for this process
    let mut vm = vm_create();

    // Dump capabilities for debugging
    println!("HV_VMX_CAP_PINBASED:      {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED));
    println!("HV_VMX_CAP_PROCBASED:     {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED));
    println!("HV_VMX_CAP_PROCBASED2:    {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2));
    println!("HV_VMX_CAP_ENTRY:         {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY));
    println!("HV_VMX_CAP_EXIT:          {:x}", read_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT));

    // Create 1MB real mode memory region 
    let ram_region = vm_alloc_memory_region(0x100000);
    vm_map_memory_region(&mut vm, 0x0, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, ram_region.clone());

    // Put software breakpoints everywhere
    unsafe {
        memset(ram_region.data as *mut u8, 0xCC, ram_region.size);
    }

    // Create and init vcpu
    let vcpu: hv_vcpuid_t = vm_vcpu_create();
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_PIN_BASED, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED, 0
        /*| PIN_BASED_INTR*/
        /*| PIN_BASED_NMI*/
        /*| PIN_BASED_VIRTUAL_NMI*/));

    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED, (0 
        | CPU_BASED_HLT
        | CPU_BASED_CR8_LOAD
        | CPU_BASED_CR8_STORE
        | CPU_BASED_SECONDARY_CTLS) as u32));
    
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CPU_BASED2, check_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2, 0
        /*| CPU_BASED2_EPT*/
        | CPU_BASED2_UNRESTRICTED as u32));

    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_VMENTRY_CONTROLS, check_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY, 0));
    wvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_VMEXIT_CONTROLS, check_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT, 0));

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_EXC_BITMAP, 0 
        | (1 << 1)
        | (1 << 3)
        );

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_MASK, 0x60000000);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR0_SHADOW, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_MASK, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_CTRL_CR4_SHADOW, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_AR, 0x9b);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE, 0xfffffff0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_DS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_ES_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_FS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_LIMIT, 0xffff);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_AR, 0x93);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_SS_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_AR, 0x10000);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_LDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_AR, 0x83);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_TR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_GDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_IDTR_LIMIT, 0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_IDTR_BASE, 0);

    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0, 0x20);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR3, 0x0);
    wvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR4, 0x2000);

    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RIP, 0x0);
    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RFLAGS, 0x2);
    write_guest_reg(vcpu, hv_x86_reg_t::HV_X86_RSP, 0x0);

    // Run vm loop
    loop {
        let err = vm_run(vcpu);
        let exit_reason = rvmcs32(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_REASON);
        let exit_qualif = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_QUALIFIC);

        println!("VM run returned {:x}", err);
        println!("Exit reason {:x} ({})", exit_reason, exit_reason & 0xFFFF);

        if err != HV_SUCCESS {
            break;
        }

        dump_guest_state(vcpu);

        let reason: hv_vmx_exit_reason = hv_vmx_exit_reason::from_u32(exit_reason).unwrap();

        match reason {
            hv_vmx_exit_reason::VMX_REASON_EXC_NMI => {
                println!("VMX_REASON_EXC_NMI");
                println!("VMCS_RO_IDT_VECTOR_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_INFO));
                println!("VMCS_RO_IDT_VECTOR_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_ERROR));
                println!("VMCS_RO_VMEXIT_IRQ_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_INFO));
                println!("VMCS_RO_VMEXIT_IRQ_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_ERROR));
            },

            hv_vmx_exit_reason::VMX_REASON_IRQ => {
                println!("VMX_REASON_IRQ");
                println!("VMCS_RO_IDT_VECTOR_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_INFO));
                println!("VMCS_RO_IDT_VECTOR_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_IDT_VECTOR_ERROR));
                println!("VMCS_RO_VMEXIT_IRQ_INFO = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_INFO));
                println!("VMCS_RO_VMEXIT_IRQ_ERROR = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_VMEXIT_IRQ_ERROR));
            }

            hv_vmx_exit_reason::VMX_REASON_IO => {
                let port: u16 = ((exit_qualif >> 16) & 0xFFFF) as u16; 
                let is_read: bool = (exit_qualif & 0x8) != 0;
                println!("IO to port {:x}, {}", port, is_read);
            }

            hv_vmx_exit_reason::VMX_REASON_EPT_VIOLATION => {
                println!("VMX_REASON_EPT_VIOLATION");
            }


            _ => {
                println!("Unhandled exit reason");
                panic!();
            }
        }
    }
}