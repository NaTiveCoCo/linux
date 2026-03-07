// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <asm/cacheflush.h>

#include <asm/sbi.h>

#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/page.h>
#include <asm/processor.h>

#include <asm/io.h>

#define NACC_BASE_MAPPINGS 0x17ff00000
#define NACC_MAPPINGS_SIZE 0x100000

#define NACC_AGENT_MEM_SIZE        0x20000000

extern unsigned long nacc_mappings_virt;

extern char do_irq[];
extern char excp_vect_table[];


static long riscv_sys_mmap(unsigned long addr, unsigned long len,
			   unsigned long prot, unsigned long flags,
			   unsigned long fd, off_t offset,
			   unsigned long page_shift_offset)
{
	if (unlikely(offset & (~PAGE_MASK >> page_shift_offset)))
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd,
			       offset >> (PAGE_SHIFT - page_shift_offset));
}

#ifdef CONFIG_64BIT
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 0);
}
#endif

#if defined(CONFIG_32BIT) || defined(CONFIG_COMPAT)
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	/*
	 * Note that the shift for mmap2 is constant (12),
	 * regardless of PAGE_SIZE
	 */
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 12);
}
#endif

/*
 * Allows the instruction cache to be flushed from userspace.  Despite RISC-V
 * having a direct 'fence.i' instruction available to userspace (which we
 * can't trap!), that's not actually viable when running on Linux because the
 * kernel might schedule a process on another hart.  There is no way for
 * userspace to handle this without invoking the kernel (as it doesn't know the
 * thread->hart mappings), so we've defined a RISC-V specific system call to
 * flush the instruction cache.
 *
 * sys_riscv_flush_icache() is defined to flush the instruction cache over an
 * address range, with the flush applying to either all threads or just the
 * caller.  We don't currently do anything with the address range, that's just
 * in there for forwards compatibility.
 */
SYSCALL_DEFINE3(riscv_flush_icache, uintptr_t, start, uintptr_t, end,
	uintptr_t, flags)
{
	/* Check the reserved flags. */
	if (unlikely(flags & ~SYS_RISCV_FLUSH_ICACHE_ALL))
		return -EINVAL;

	flush_icache_mm(current->mm, flags & SYS_RISCV_FLUSH_ICACHE_LOCAL);

	return 0;
}

void nacc_invoke(void)
{
    unsigned long pid = current->pid;
    unsigned long current_gp = 0;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);
    
    /* 
     * Set from preparation state to real nacc state.
     * Here we still don't have to reclaim.
     */
    current->thread.nacc_flag = NACC_INITED;
    
    /* 
     * First allocate a contiguous virtual memory region to the process, for agent.
     * Then transfer the PTP.
     */
    printk(KERN_ERR "[Linux]: start_thread is invoked for NACC process. \n");
    virt_agent = get_unmapped_area(NULL, TASK_UNMAPPED_BASE, NACC_AGENT_MEM_SIZE, 0, 0);
    struct vm_area_struct *vma = vm_area_alloc(current->mm);
    vma->vm_start = virt_agent;
    vma->vm_end = virt_agent + NACC_AGENT_MEM_SIZE;

    /* This VMA region should not be included in normal procedure. */
    vm_flags_init(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_NACC);
    vma->vm_page_prot = pgprot_noncached(PAGE_NONE);

    if (insert_vm_struct(current->mm, vma)) {
        printk(KERN_ERR "[Linux]: failed to insert VMA for NACC agent.\n");
        vm_area_free(vma);
        return;
    }

    printk(KERN_ERR "[Linux]: Found an unmapped region with virt_agent %lx\n", virt_agent);

    asm volatile("mv %0, gp" : "=r"(current_gp));

    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE, virt_agent, pid, (unsigned long) regs, (unsigned long) do_irq, (unsigned long) excp_vect_table, current_gp);
}

void nacc_invoke_child(void)
{
    /*
     * For fork + exec cases.
     * The agent region (VM_NACC) is already initialized by the parent.
     * We only need to:
     * 1. Register child PID with parent's CID (done in OpenSBI)
     * 2. Transfer PTP for the child's new page table (done in OpenSBI)
     * 3. Map agent region into child's address space (done in OpenSBI)
     * No agent jump needed — child stays in Linux.
     */
    unsigned long pid = current->pid;
    unsigned long virt_agent = 0;
    unsigned long cid = current->thread.nacc_cid;

    printk(KERN_ERR "[Linux]: NaCC forked child process, pid=%lu, cid=%lx\n", pid, cid);

    /* Set the nacc_flag to INITED since we're entering NaCC protection. */
    current->thread.nacc_flag = NACC_INITED;

    /* Allocate a VMA for the agent region in the child's address space. */
    virt_agent = get_unmapped_area(NULL, TASK_UNMAPPED_BASE, NACC_AGENT_MEM_SIZE, 0, 0);
    struct vm_area_struct *vma = vm_area_alloc(current->mm);
    vma->vm_start = virt_agent;
    vma->vm_end = virt_agent + NACC_AGENT_MEM_SIZE;

    /* This VMA region should not be included in normal procedure. */
    vm_flags_init(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_NACC);
    vma->vm_page_prot = pgprot_noncached(PAGE_NONE);

    if (insert_vm_struct(current->mm, vma)) {
        printk(KERN_ERR "[Linux]: failed to insert VMA for NACC agent (child).\n");
        vm_area_free(vma);
        return;
    }

    printk(KERN_ERR "[Linux]: Child found unmapped region with virt_agent %lx\n", virt_agent);

    /* Call into OpenSBI to register child, transfer PTP, and map agent.
     * We pass the cid explicitly to allow OpenSBI to register this child properly.
     * The remaining args are unused since we don't jump into agent. */
    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE_CHILD, virt_agent, pid,
              cid, 0, 0, 0);

    printk(KERN_ERR "[Linux]: nacc_invoke_child done, child continues in Linux.\n");
}

void nacc_fork(unsigned long parent_pgd_pa, unsigned long child_pgd_pa)
{
    printk(KERN_ERR "[Linux]: nacc_fork: parent_pgd=%lx child_pgd=%lx\n",
           parent_pgd_pa, child_pgd_pa);

    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FORK, parent_pgd_pa, child_pgd_pa,
              0, 0, 0, 0);

    printk(KERN_ERR "[Linux]: nacc_fork done.\n");
}

SYSCALL_DEFINE1(nacc_register, unsigned long, cid)
{
    unsigned long pid;
    printk(KERN_ERR "[Linux] register a new NACC process. \n");

    /*
     * Mark the current process as nacc process here.
     * However, as the preparation state.
     */
    current->thread.nacc_flag = NACC_PREPARE;
    current->thread.nacc_cid = cid;

    pid = current->pid;
    printk(KERN_ERR "[Linux]: container id is %lx. \n", cid);

    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, pid, 0, 0, 0, 0);

    printk(KERN_ERR "[Linux]: GO BACK TO RUNC. \n");

    return 0;
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
