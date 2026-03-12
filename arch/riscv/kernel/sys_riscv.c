// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/mm.h>
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
#define NACC_AGENT_SLOT_SIZE       0x40000000UL
#define NACC_AGENT_TOP_GAP         0x100000000UL
#define NACC_FORK_PTP_LIST_PAGES   2

extern unsigned long nacc_mappings_virt;

extern char do_irq[];
extern char excp_vect_table[];

static unsigned long nacc_fixed_agent_base(void)
{
    if (TASK_SIZE <= NACC_AGENT_SLOT_SIZE + NACC_AGENT_TOP_GAP)
        return 0;

    return TASK_SIZE - NACC_AGENT_TOP_GAP - NACC_AGENT_SLOT_SIZE;
}

int nacc_reserve_agent_slot_mm(struct mm_struct *mm, const char *tag)
{
    unsigned long virt_agent;
    unsigned long virt_end;
    struct vm_area_struct *vma;
    struct vm_area_struct *conflict;
    int ret;

    virt_agent = nacc_fixed_agent_base();
    virt_end = virt_agent + NACC_AGENT_SLOT_SIZE;
    if (!virt_agent || virt_end > TASK_SIZE) {
        printk(KERN_ERR "[Linux]: invalid fixed NACC agent slot (%s): [%lx, %lx) task_size=%lx\n",
               tag, virt_agent, virt_end, TASK_SIZE);
        return -EINVAL;
    }

    ret = mmap_write_lock_killable(mm);
    if (ret)
        return ret;

    conflict = find_vma_intersection(mm, virt_agent, virt_end);
    if (conflict) {
        if (conflict->vm_start == virt_agent && conflict->vm_end == virt_end &&
            (conflict->vm_flags & VM_NACC)) {
            mmap_write_unlock(mm);
            return 0;
        }

        printk(KERN_ERR "[Linux]: fixed NACC agent slot is occupied (%s): [%lx, %lx) conflicts with VMA [%lx, %lx)\n",
               tag, virt_agent, virt_end, conflict->vm_start, conflict->vm_end);
        mmap_write_unlock(mm);
        return -EEXIST;
    }

    vma = vm_area_alloc(mm);
    if (!vma) {
        printk(KERN_ERR "[Linux]: failed to allocate VMA for NACC agent (%s).\n",
               tag);
        mmap_write_unlock(mm);
        return -ENOMEM;
    }

    vma->vm_start = virt_agent;
    vma->vm_end = virt_end;

    /*
     * Reserve one full SV39 VPN[2] slot (1 GiB). OpenSBI will only map the
     * first NACC_AGENT_MEM_SIZE bytes with actual agent PTEs; the rest stays
     * as guard hole so ELF/mmap do not share the same top-level slot.
     */
    vm_flags_init(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_NACC);
    vma->vm_page_prot = pgprot_noncached(PAGE_NONE);

    ret = insert_vm_struct(mm, vma);
    if (ret) {
        printk(KERN_ERR "[Linux]: failed to insert VMA for NACC agent slot (%s), ret=%d.\n",
               tag, ret);
        mmap_write_unlock(mm);
        vm_area_free(vma);
        return ret;
    }

    mmap_write_unlock(mm);

    printk(KERN_ERR "[Linux]: reserved fixed NACC agent slot (%s): [%lx, %lx), active agent range [%lx, %lx)\n",
           tag, virt_agent, virt_end, virt_agent, virt_agent + NACC_AGENT_MEM_SIZE);

    return 0;
}

static int nacc_insert_agent_vma(unsigned long *virt_agent_out,
                                 const char *tag)
{
    unsigned long virt_agent;
    unsigned long slot_end;
    struct vm_area_struct *slot;

    virt_agent = nacc_fixed_agent_base();
    slot_end = virt_agent + NACC_AGENT_SLOT_SIZE;
    if (!virt_agent || slot_end > TASK_SIZE)
        return -EINVAL;

    slot = find_vma_intersection(current->mm, virt_agent, slot_end);
    if (!slot) {
        int ret = nacc_reserve_agent_slot_mm(current->mm, tag);
        if (ret)
            return ret;
        slot = find_vma_intersection(current->mm, virt_agent, slot_end);
    }

    if (!slot || slot->vm_start != virt_agent || slot->vm_end != slot_end ||
        !(slot->vm_flags & VM_NACC)) {
        printk(KERN_ERR "[Linux]: fixed NACC agent slot missing or malformed (%s): expected [%lx, %lx)\n",
               tag, virt_agent, slot_end);
        return -ENOMEM;
    }

    *virt_agent_out = virt_agent;
    return 0;
}

static void __nacc_invoke_full(unsigned long sbi_fid, const char *tag)
{
    unsigned long pid = current->pid;
    unsigned long current_gp = 0;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);

    /*
     * Full invoke path:
     * - insert a fresh VM_NACC VMA in the new mm
     * - enter OpenSBI with complete host/trap context so agent-side
     *   state gets refreshed before the next user trap
     */
    current->thread.nacc_flag = NACC_INITED;

    if (nacc_insert_agent_vma(&virt_agent, tag))
        return;

    printk(KERN_ERR "[Linux]: %s using virt_agent %lx\n", tag, virt_agent);

    asm volatile("mv %0, gp" : "=r"(current_gp));

    sbi_ecall(SBI_EXT_NACC, sbi_fid, virt_agent, pid, (unsigned long) regs,
              (unsigned long) do_irq, (unsigned long) excp_vect_table,
              current_gp);
}


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
    printk(KERN_ERR "[Linux]: start_thread is invoked for NACC process. \n");
    __nacc_invoke_full(SBI_EXT_NACC_INVOKE, "nacc_invoke");
}

void nacc_reexec(void)
{
    unsigned long pid = current->pid;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);
    struct sbiret ret;

    /*
     * Same-PID re-exec must not reuse fork-child re-attach semantics.
     * Part 1 keeps the ABI minimal:
     * - install a fresh VM_NACC VMA for the new mm
     * - hand the new user pt_regs to OpenSBI
     * Trap-context refresh inside agent/OpenSBI is handled separately.
     */
    printk(KERN_ERR "[Linux]: NACC_REEXEC preparing minimal reattach path.\n");

    if (nacc_insert_agent_vma(&virt_agent, "nacc_reexec"))
        return;

    printk(KERN_ERR "[Linux]: nacc_reexec using virt_agent %lx\n", virt_agent);

    /*
     * Re-exec now follows the same "non-returning" shape as nacc_invoke():
     * OpenSBI enters the agent and the agent returns directly to userspace.
     * Set INITED before the SBI transition so later kernel entries don't keep
     * seeing the transient REEXEC flag forever.
     */
    current->thread.nacc_flag = NACC_INITED;

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REEXEC, virt_agent, pid,
                    (unsigned long) regs, 0, 0, 0);

    if (ret.error) {
        current->thread.nacc_flag = NACC_REEXEC;
        printk(KERN_ERR "[Linux]: nacc_reexec SBI returned unexpectedly with error %ld\n",
               ret.error);
    }
}

void nacc_invoke_child(void)
{
    /*
     * For fork + exec cases only.
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

    printk(KERN_ERR "[Linux]: NaCC re-attach process, pid=%lu, cid=%lx\n", pid, cid);

    if (nacc_insert_agent_vma(&virt_agent, "nacc_invoke_child"))
        return;

    printk(KERN_ERR "[Linux]: Child re-attach uses fixed virt_agent %lx\n",
           virt_agent);

    /* Call into OpenSBI to register child, transfer PTP, and map agent.
     * We pass the cid explicitly to allow OpenSBI to register this child properly.
     * The remaining args are unused since we don't jump into agent. */
    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE_CHILD, virt_agent, pid,
              cid, 0, 0, 0);

    /*
     * Mark as INITED only after OpenSBI re-attach completes and NACC_STATE
     * has been switched to LINUX in M-mode.
     */
    current->thread.nacc_flag = NACC_INITED;

    printk(KERN_ERR "[Linux]: nacc_invoke_child done, child continues in Linux.\n");
}

int nacc_fork(unsigned long parent_pgd_pa, unsigned long child_pgd_pa)
{
    unsigned long ptp_list_bytes = PAGE_SIZE * NACC_FORK_PTP_LIST_PAGES;
    struct nacc_fork_ptp_list *ptp_list;
    unsigned long capacity;
    struct sbiret ret;
    int rc;

    printk(KERN_ERR "[Linux]: nacc_fork: parent_pgd=%lx child_pgd=%lx\n",
           parent_pgd_pa, child_pgd_pa);

    ptp_list = kzalloc(ptp_list_bytes, GFP_KERNEL);
    if (!ptp_list)
        return -ENOMEM;

    capacity = (ptp_list_bytes - sizeof(*ptp_list)) /
               sizeof(ptp_list->entries[0]);

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FORK, parent_pgd_pa,
                    child_pgd_pa, virt_to_phys(ptp_list), ptp_list_bytes,
                    0, 0);
    if (ret.error) {
        printk(KERN_ERR "[Linux]: nacc_fork failed: sbi error=%ld value=%ld\n",
               ret.error, ret.value);
        kfree(ptp_list);
        return -EIO;
    }

    rc = nacc_register_fork_ptp_list(ptp_list, ptp_list_bytes);
    if (rc) {
        printk(KERN_ERR "[Linux]: nacc_fork ptp_list register failed: %d "
               "(nr=%u cap=%lu)\n",
               rc, ptp_list->nr_entries, capacity);
        kfree(ptp_list);
        return rc;
    }

    printk(KERN_ERR "[Linux]: nacc_fork ptp_list entries=%u\n",
           ptp_list->nr_entries);
    kfree(ptp_list);

    printk(KERN_ERR "[Linux]: nacc_fork done.\n");
    return 0;
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
