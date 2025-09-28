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

#include <asm/io.h>

extern char do_irq[];
extern char excp_vect_table[];

extern unsigned long __global_pointer$;

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

SYSCALL_DEFINE2(nacc_invoke, unsigned long, cid, unsigned long, agent_virt_start)
{
    struct pt_regs *regs = task_pt_regs(current);
    
    /*
     * Mark the current process as nacc process.
     * Else the linux don't know how to handle it.
     */
    current->thread.nacc_flag = 1; 

    unsigned long current_gp;

    printk(KERN_ERR "[Linux]: runc init has invoked the linux to handle the invocation process. \n");

    printk(KERN_ERR "[Linux]: container id is %lx. \n", cid);

	printk(KERN_ERR "[Linux]: pt_regs details:\n");
    printk(KERN_ERR "[Linux]: epc (pc): 0x%lx\n", regs->epc);
    printk(KERN_ERR "[Linux]: ra (x1): 0x%lx\n", regs->ra);
    printk(KERN_ERR "[Linux]: sp (x2): 0x%lx\n", regs->sp);
    printk(KERN_ERR "[Linux]: gp (x3): 0x%lx\n", regs->gp);
    printk(KERN_ERR "[Linux]: tp (x4): 0x%lx\n", regs->tp);
    printk(KERN_ERR "[Linux]: t0 (x5): 0x%lx\n", regs->t0);
    printk(KERN_ERR "[Linux]: t1 (x6): 0x%lx\n", regs->t1);
    printk(KERN_ERR "[Linux]: t2 (x7): 0x%lx\n", regs->t2);
    printk(KERN_ERR "[Linux]: s0 (x8): 0x%lx\n", regs->s0);
    printk(KERN_ERR "[Linux]: s1 (x9): 0x%lx\n", regs->s1);
    printk(KERN_ERR "[Linux]: a0 (x10): 0x%lx\n", regs->a0);
    printk(KERN_ERR "[Linux]: a1 (x11): 0x%lx\n", regs->a1);
    printk(KERN_ERR "[Linux]: a2 (x12): 0x%lx\n", regs->a2);
    printk(KERN_ERR "[Linux]: a3 (x13): 0x%lx\n", regs->a3);
    printk(KERN_ERR "[Linux]: a4 (x14): 0x%lx\n", regs->a4);
    printk(KERN_ERR "[Linux]: a5 (x15): 0x%lx\n", regs->a5);
    printk(KERN_ERR "[Linux]: a6 (x16): 0x%lx\n", regs->a6);
    printk(KERN_ERR "[Linux]: a7 (x17): 0x%lx\n", regs->a7);
    printk(KERN_ERR "[Linux]: s2 (x18): 0x%lx\n", regs->s2);
    printk(KERN_ERR "[Linux]: s3 (x19): 0x%lx\n", regs->s3);
    printk(KERN_ERR "[Linux]: s4 (x20): 0x%lx\n", regs->s4);
    printk(KERN_ERR "[Linux]: s5 (x21): 0x%lx\n", regs->s5);
    printk(KERN_ERR "[Linux]: s6 (x22): 0x%lx\n", regs->s6);
    printk(KERN_ERR "[Linux]: s7 (x23): 0x%lx\n", regs->s7);
    printk(KERN_ERR "[Linux]: s8 (x24): 0x%lx\n", regs->s8);
    printk(KERN_ERR "[Linux]: s9 (x25): 0x%lx\n", regs->s9);
    printk(KERN_ERR "[Linux]: s10 (x26): 0x%lx\n", regs->s10);
    printk(KERN_ERR "[Linux]: s11 (x27): 0x%lx\n", regs->s11);
    printk(KERN_ERR "[Linux]: t3 (x28): 0x%lx\n", regs->t3);
    printk(KERN_ERR "[Linux]: t4 (x29): 0x%lx\n", regs->t4);
    printk(KERN_ERR "[Linux]: t5 (x30): 0x%lx\n", regs->t5);
    printk(KERN_ERR "[Linux]: t6 (x31): 0x%lx\n", regs->t6);
    printk(KERN_ERR "[Linux]: status: 0x%lx\n", regs->status);
    printk(KERN_ERR "[Linux]: badaddr: 0x%lx\n", regs->badaddr);
    printk(KERN_ERR "[Linux]: cause: 0x%lx\n", regs->cause);
    printk(KERN_ERR "[Linux]: orig_a0: 0x%lx\n", regs->orig_a0);
	/*
     * Invoke an SBI call to the OpenSBI.
	 */

	printk(KERN_ERR "[Linux]: regs is %lx. \n", (unsigned long) regs);

    printk(KERN_ERR "[Linux]: allocate a portion of memory for shared memory with agent. \n");

    // char* shared_mem = (char*) kmalloc(2 * PAGE_SIZE, GFP_KERNEL);

    asm volatile("mv %0, gp" : "=r"(current_gp));

    /*
     * The first page will be used to transfer pt_regs info, while the second will transfer other info.
     */
    
    
    struct sbiret ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE, cid, agent_virt_start, (unsigned long) regs, (unsigned long) do_irq, (unsigned long) excp_vect_table, current_gp);

    if (ret.error) {
		pr_err("[Linux]: SBI call SBI_EXT_NACC_INVOKE failed with error %lx\n", ret.error);
		return -1;
	}

    printk(KERN_ERR "[Linux]: GO BACK TO RUNC. \n");

	return 0;
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
