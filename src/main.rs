#![allow(non_snake_case)] 

extern crate rlibc;
extern crate num;
extern crate Hypervisor_framework;

mod memory;

use Hypervisor_framework::*;
use memory::*;
use rlibc::*;

//#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
	fn valloc(size: usize) -> *mut ::std::os::raw::c_void;
}

fn rvmcs(vcpu: hv_vcpuid_t, field: u32) -> u64
{
	unsafe {
		let mut v: u64 = 0;
		let res = hv_vmx_vcpu_read_vmcs(vcpu, field, &mut v);
		assert!(res == hv_return::HV_SUCCESS as i32);
		return v;
	}
}

fn wvmcs(vcpu: hv_vcpuid_t, field: u32, v: u64) 
{
	unsafe {
		let res = hv_vmx_vcpu_write_vmcs(vcpu, field, v);
		assert!(res == hv_return::HV_SUCCESS as i32);
	}
}

fn read_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t) -> u64
{
	unsafe {
		let mut v: u64 = 0;
		let res = hv_vcpu_read_register(vcpu, reg, &mut v);
		assert!(res == hv_return::HV_SUCCESS as i32);
		return v;
	}
} 

fn write_guest_reg(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, v: u64)
{
	unsafe {
		let res = hv_vcpu_write_register(vcpu, reg, v);
		assert!(res == hv_return::HV_SUCCESS as i32);
	}
} 

fn check_cap(capid: hv_vmx_capability_t, val: u32) -> u32 
{
	let mut cap: u64 = 0;
	unsafe {
		let res = hv_vmx_read_capability(capid, &mut cap);
		assert!(res == hv_return::HV_SUCCESS as i32);
	}

	let cap = cap; // Drop mutability
	let cap_low: u32 = (cap & 0xFFFFFFFF) as u32;
	let cap_high: u32 = ((cap >> 32) & 0xFFFFFFFF) as u32;

	(val | cap_low) & cap_high
}

fn dump_guest_state(vcpu: hv_vcpuid_t)
{
	println!(" Guest state: ");

	let rip = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RIP as u32);
	let cs_base = rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CS_BASE as u32);
	let gpa = cs_base + rip;
	println!(" RIP {:x} (CS {:x}, PA {:x})", rip, cs_base, gpa);

	println!(" CR0 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR0 as u32));
	println!(" CR3 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR3 as u32));
	println!(" CR4 = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_CR4 as u32));
	println!(" EFLAGS = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_GUEST_RFLAGS as u32));
	println!(" GLA = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_GUEST_LIN_ADDR as u32));
	println!(" EXITQ = {:x}", rvmcs(vcpu, hv_vmx_vmcs_regs::VMCS_RO_EXIT_QUALIFIC as u32));
}

fn main() {

	let vm_memory_bytes: usize = 0x100000;
	let mut err: hv_return_t = hv_return::HV_SUCCESS as i32;

	unsafe {
		err = hv_vm_create(hv_vm_options::HV_VM_DEFAULT as u64);
		assert!(err == hv_return::HV_SUCCESS as i32);

		let hostva = valloc(vm_memory_bytes);
		if hostva.is_null() {
			println!("allocation failed");
			panic!();
		}

		println!("Guest memory at {:p}", hostva);

		let hostva_u8 = hostva as *mut u8;

		memset(hostva_u8, 0xCC, vm_memory_bytes);
		*hostva_u8.offset(0x100) = 0xEB;
		*hostva_u8.offset(0x101) = 0xFE;

		err = hv_vm_map(hostva, 0, vm_memory_bytes, 
			hv_memory_flags::HV_MEMORY_READ as u64 | hv_memory_flags::HV_MEMORY_WRITE as u64 | hv_memory_flags::HV_MEMORY_EXEC as u64);

		assert!(err == hv_return::HV_SUCCESS as i32);

		let mut vcpu: hv_vcpuid_t = 0;
		err = hv_vcpu_create(&mut vcpu, hv_vcpu_options::HV_VCPU_DEFAULT as u64);
		assert!(err == hv_return::HV_SUCCESS as i32);
	
		let mut cap: u64 = 0;

		hv_vmx_read_capability(hv_vmx_capability_t::HV_VMX_CAP_PINBASED, &mut cap);
		println!("HV_VMX_CAP_PINBASED: 		{:x}", cap);

		hv_vmx_read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED, &mut cap);
		println!("HV_VMX_CAP_PROCBASED: 	{:x}", cap);

		hv_vmx_read_capability(hv_vmx_capability_t::HV_VMX_CAP_PROCBASED2, &mut cap);
		println!("HV_VMX_CAP_PROCBASED2: 	{:x}", cap);

		hv_vmx_read_capability(hv_vmx_capability_t::HV_VMX_CAP_ENTRY, &mut cap);
		println!("HV_VMX_CAP_ENTRY: 		{:x}", cap);

		hv_vmx_read_capability(hv_vmx_capability_t::HV_VMX_CAP_EXIT, &mut cap);
		println!("HV_VMX_CAP_EXIT: 			{:x}", cap);

	}

/*

	wvmcs(vcpu, VMCS_CTRL_PIN_BASED, check_cap(HV_VMX_CAP_PINBASED, 0
												/*| PIN_BASED_INTR*/
												/*| PIN_BASED_NMI*/
												/*| PIN_BASED_VIRTUAL_NMI*/));
	
	wvmcs(vcpu, VMCS_CTRL_CPU_BASED, check_cap(HV_VMX_CAP_PROCBASED, 0 
												| CPU_BASED_HLT
												| CPU_BASED_CR8_LOAD
												| CPU_BASED_CR8_STORE
												| CPU_BASED_SECONDARY_CTLS));
	
	wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, check_cap(HV_VMX_CAP_PROCBASED2, 0
												/*| CPU_BASED2_EPT*/
												| CPU_BASED2_UNRESTRICTED));

	wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, check_cap(HV_VMX_CAP_ENTRY, 0));

	wvmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, check_cap(HV_VMX_CAP_EXIT, 0));

	wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0 
		| (1ul << 1)
		| (1ul << 3)
		);

	wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0x60000000);
	wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0);
	wvmcs(vcpu, VMCS_CTRL_CR4_MASK, 0);
	wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

	wvmcs(vcpu, VMCS_GUEST_CS, 0);
	wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_CS_AR, 0x9b);
	wvmcs(vcpu, VMCS_GUEST_CS_BASE, 0xfffffff0);

	wvmcs(vcpu, VMCS_GUEST_DS, 0);
	wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_DS_AR, 0x93);
	wvmcs(vcpu, VMCS_GUEST_DS_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_ES, 0);
	wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_ES_AR, 0x93);
	wvmcs(vcpu, VMCS_GUEST_ES_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_FS, 0);
	wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_FS_AR, 0x93);
	wvmcs(vcpu, VMCS_GUEST_FS_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_GS, 0);
	wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_GS_AR, 0x93);
	wvmcs(vcpu, VMCS_GUEST_GS_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_SS, 0);
	wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffff);
	wvmcs(vcpu, VMCS_GUEST_SS_AR, 0x93);
	wvmcs(vcpu, VMCS_GUEST_SS_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_LDTR, 0);
	wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0);
	wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000);
	wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_TR, 0);
	wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
	wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x83);
	wvmcs(vcpu, VMCS_GUEST_TR_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0);
	wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);
	wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);

	wvmcs(vcpu, VMCS_GUEST_CR0, 0x20);
	wvmcs(vcpu, VMCS_GUEST_CR3, 0x0);
	wvmcs(vcpu, VMCS_GUEST_CR4, 0x2000);

	wreg(vcpu, HV_X86_RIP, 0x0);
	wreg(vcpu, HV_X86_RFLAGS, 0x2);
	wreg(vcpu, HV_X86_RSP, 0x0);

	// Load bios image and map it for vm

	size_t bios_image_size = 0;
	void* bios_image = map_bios_image(&bios_image_size);
	if (!bios_image) {
		printf("Failed to map bios image\n");
		return EXIT_FAILURE;
	}

	printf("BIOS image size is %d\n", bios_image_size);

	err = hv_vm_map(bios_image, 0x100000000ull - bios_image_size, bios_image_size, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
	if (err != HV_SUCCESS) {
		fprintf(stderr, "bios image mapping high failed with 0x%x\n", err);
		return EXIT_FAILURE;
	}

	err = hv_vm_map(bios_image, 0x100000 - bios_image_size, bios_image_size, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
	if (err != HV_SUCCESS) {
		fprintf(stderr, "bios image mapping low failed with 0x%x\n", err);
		return EXIT_FAILURE;
	}

	warm_pages(bios_image, bios_image_size / 4096);

	hv_vcpu_flush(vcpu);
	hv_vcpu_invalidate_tlb(vcpu);
	hv_vcpu_flush(vcpu);
	while (1) {
		err = hv_vcpu_run(vcpu);
		uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);
		uint64_t exit_qualif = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);

		printf("VM run returned 0x%016llx\n", err);
		printf("Exit reason %016llx (%d)\n", exit_reason, exit_reason & 0xFFFF);
		if (err != HV_SUCCESS) {
			break;
		}

		dump_guest_state(vcpu);

		switch(exit_reason) {
			case VMX_REASON_EXC_NMI: {
				//printf("VMX_REASON_EXC_NMI\n");
				//printf("VMCS_RO_IDT_VECTOR_INFO = 0x%x\n", rvmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO));
				//printf("VMCS_RO_IDT_VECTOR_ERROR = 0x%x\n", rvmcs(vcpu, VMCS_RO_IDT_VECTOR_ERROR));
				//printf("VMCS_RO_VMEXIT_IRQ_INFO = 0x%x\n", rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO));
				//printf("VMCS_RO_VMEXIT_IRQ_ERROR = 0x%x\n", rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR));
				break;
			}

			case VMX_REASON_IRQ: {
				//printf("VMX_REASON_IRQ\n");
				//printf("VMCS_RO_IDT_VECTOR_INFO = 0x%x\n", rvmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO));
				//printf("VMCS_RO_IDT_VECTOR_ERROR = 0x%x\n", rvmcs(vcpu, VMCS_RO_IDT_VECTOR_ERROR));
				//printf("VMCS_RO_VMEXIT_IRQ_INFO = 0x%x\n", rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO));
				//printf("VMCS_RO_VMEXIT_IRQ_ERROR = 0x%x\n", rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR));
				break;
			}

			case VMX_REASON_IO: {
				uint16_t port = (exit_qualif >> 16) & 0xFFFF; 
				bool read = (exit_qualif & 0x8) != 0;
				printf("IO to port 0x%x, %s\n", port, (read ? "read" : "write"));
				break;
			}

			case VMX_REASON_EPT_VIOLATION: {
				printf("VMX_REASON_EPT_VIOLATION\n");
				break;
			}


			default: {
				printf("Unhandled exit reason\n");
				return EXIT_FAILURE;
			}
		};

	}

	return EXIT_SUCCESS;
	*/
}
