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

SYSCALL_DEFINE1(nacc_invoke, unsigned long, cid)
{
    printk(KERN_ERR "[Linux]: runc init has invoked the linux to handle the invokion process. \n");

    printk(KERN_ERR "[Linux]: container id is %lx. \n", cid);

    /*
     * Allocate an emptry page to fetch the PPN, and later free them manually.
     */
    unsigned long *tmp_page = kmalloc(PAGE_SIZE, GFP_KERNEL);
    unsigned long pa = __pa(tmp_page);
    memset(tmp_page, 0, PAGE_SIZE);
    /*
     * Invoke an SBI call to the OpenSBI.
     */
	struct sbiret ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE, cid, pa, 0, 0, 0, 0);
	
	if (ret.error) {
		pr_err("SBI call SBI_EXT_NACC_INVOKE failed with error %d\n", ret.error);
		return -1;
	}

    printk(KERN_ERR "[Linux]: You should see me?\n");
    
    printk(KERN_ERR "[Linux]: tmp_page is at 0x%lx, pa is 0x%lx, we try to access it.\n", (unsigned long)tmp_page, pa);
    printk(KERN_ERR "[Linux]: tmp_page First 8 Bytes: %lx\n", *tmp_page);
    

    /*
     * tmp_page will be filled with the unused PPN of the container.
     * So we manually go over the tmp_page to free them.
     */
    for(unsigned long i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
        unsigned long page_to_free = *(tmp_page + i);
        if (page_to_free == 0) {
            break;  // Stop on zero entry
        }
        printk(KERN_ERR "[Linux]: freeing page 0x%lx\n", page_to_free);
        __free_page(phys_to_page(page_to_free));
    }

    kfree(tmp_page);

    printk(KERN_ERR "[Linux]: GO BACK TO RUNC. \n");
    return 0;
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
