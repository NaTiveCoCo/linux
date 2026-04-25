// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
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
#define NACC_MANIFEST_REGISTRY_SLOTS 32
#define NACC_MANIFEST_LAYOUT_MAX_RECORDS 16
#define NACC_MANIFEST_PATH_MAX      192
#define NACC_MANIFEST_SHA256_BYTES  32
extern char do_irq[];
extern char excp_vect_table[];

struct nacc_manifest_identity {
	char path[NACC_MANIFEST_PATH_MAX];
	u8 sha256[NACC_MANIFEST_SHA256_BYTES];
	u64 size;
};

struct nacc_manifest_layout_record {
	u32 role;
	u32 phdr_index;
	u64 page_offset;
	u64 page_size;
	u32 flags_raw;
	u32 reserved;
};

struct nacc_manifest_registration {
	struct nacc_manifest_identity identity;
	u32 layout_record_count;
	struct nacc_manifest_layout_record
		layout_records[NACC_MANIFEST_LAYOUT_MAX_RECORDS];
};

struct nacc_manifest_registry_slot {
	unsigned long cid;
	struct nacc_manifest_registration registration;
};

static DEFINE_SPINLOCK(nacc_manifest_registry_lock);
static struct nacc_manifest_registry_slot
	nacc_manifest_registry[NACC_MANIFEST_REGISTRY_SLOTS];

static void nacc_manifest_sha256_to_hex(const u8 sha256[NACC_MANIFEST_SHA256_BYTES],
					char out[(NACC_MANIFEST_SHA256_BYTES * 2) + 1])
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < NACC_MANIFEST_SHA256_BYTES; i++) {
		out[(i * 2)] = hex[sha256[i] >> 4];
		out[(i * 2) + 1] = hex[sha256[i] & 0x0f];
	}
	out[NACC_MANIFEST_SHA256_BYTES * 2] = '\0';
}

static int nacc_copy_manifest_identity_from_user(
	struct nacc_manifest_identity *identity,
	const char __user *manifest_path,
	const u8 __user *manifest_sha256,
	u64 manifest_size)
{
	long path_len;

	path_len = strnlen_user(manifest_path, sizeof(identity->path));
	if (!path_len)
		return -EFAULT;
	if (path_len > sizeof(identity->path))
		return -ENAMETOOLONG;
	if (copy_from_user(identity->path, manifest_path, path_len))
		return -EFAULT;
	identity->path[path_len - 1] = '\0';

	if (copy_from_user(identity->sha256, manifest_sha256,
			   sizeof(identity->sha256)))
		return -EFAULT;

	identity->size = manifest_size;
	return 0;
}

static const char *nacc_manifest_object_role_name(unsigned long role)
{
	switch (role) {
	case NACC_STARTUP_OBJECT_ENTRY:
		return "entry";
	case NACC_STARTUP_OBJECT_INTERP:
		return "interp";
	default:
		return "invalid";
	}
}

static int nacc_copy_manifest_layout_from_user(
	struct nacc_manifest_registration *registration,
	const struct nacc_manifest_layout_record __user *manifest_layout,
	u64 manifest_layout_record_count)
{
	size_t bytes;
	u64 index;

	registration->layout_record_count = 0;
	memset(registration->layout_records, 0,
	       sizeof(registration->layout_records));

	if (!manifest_layout_record_count)
		return 0;
	if (!manifest_layout)
		return -EFAULT;
	if (manifest_layout_record_count > NACC_MANIFEST_LAYOUT_MAX_RECORDS)
		return -E2BIG;

	bytes = manifest_layout_record_count *
		sizeof(registration->layout_records[0]);
	if (copy_from_user(registration->layout_records, manifest_layout, bytes))
		return -EFAULT;

	for (index = 0; index < manifest_layout_record_count; index++) {
		const struct nacc_manifest_layout_record *record =
			&registration->layout_records[index];

		switch (record->role) {
		case NACC_STARTUP_OBJECT_ENTRY:
		case NACC_STARTUP_OBJECT_INTERP:
			break;
		default:
			return -EINVAL;
		}

		if (!record->page_size)
			return -EINVAL;
	}

	registration->layout_record_count = manifest_layout_record_count;
	return 0;
}

static void nacc_store_manifest_registration(
	unsigned long cid, const struct nacc_manifest_registration *registration)
{
	struct nacc_manifest_registry_slot *slot = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&nacc_manifest_registry_lock, flags);

	for (i = 0; i < NACC_MANIFEST_REGISTRY_SLOTS; i++) {
		if (nacc_manifest_registry[i].cid == cid) {
			slot = &nacc_manifest_registry[i];
			break;
		}
		if (!slot && !nacc_manifest_registry[i].cid)
			slot = &nacc_manifest_registry[i];
	}

	if (slot) {
		slot->cid = cid;
		slot->registration = *registration;
	}

	spin_unlock_irqrestore(&nacc_manifest_registry_lock, flags);

	if (!slot) {
		printk(KERN_ERR "[Linux]: nacc manifest registry full, dropping cid=%lx path=%s size=%llu layout_records=%u\n",
		       cid, registration->identity.path,
		       (unsigned long long)registration->identity.size,
		       registration->layout_record_count);
	}
}

static bool nacc_lookup_manifest_registration(
	unsigned long cid, struct nacc_manifest_registration *registration)
{
	bool found = false;
	unsigned long flags;
	int i;

	memset(registration, 0, sizeof(*registration));

	spin_lock_irqsave(&nacc_manifest_registry_lock, flags);

	for (i = 0; i < NACC_MANIFEST_REGISTRY_SLOTS; i++) {
		if (nacc_manifest_registry[i].cid != cid)
			continue;

		*registration = nacc_manifest_registry[i].registration;
		found = true;
		break;
	}

	spin_unlock_irqrestore(&nacc_manifest_registry_lock, flags);
	return found;
}

static int nacc_startup_audit_range_sbi(unsigned long root_pgd_pa,
					unsigned long cid,
					unsigned long role,
					unsigned long page_offset,
					unsigned long page_size,
					unsigned long phdr_index)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_STARTUP_AUDIT_RANGE,
			root_pgd_pa, cid, role, page_offset, page_size,
			phdr_index);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: registered manifest layout report failed: root=%lx cid=%lx role=%s phdr=%lx page_offset=%lx page_size=%lx err=%ld val=%ld\n",
		       root_pgd_pa, cid, nacc_manifest_object_role_name(role),
		       phdr_index, page_offset, page_size, ret.error,
		       ret.value);
		return -EIO;
	}

	return 0;
}

static void nacc_log_manifest_registration(unsigned long cid, unsigned long pid,
					   const struct nacc_manifest_registration *registration)
{
	char sha256_hex[(NACC_MANIFEST_SHA256_BYTES * 2) + 1];
	u32 index;

	nacc_manifest_sha256_to_hex(registration->identity.sha256, sha256_hex);
	printk(KERN_ERR "[Linux]: nacc manifest register cid=%lx pid=%lu path=%s size=%llu sha256=%s layout_records=%u\n",
	       cid, pid, registration->identity.path,
	       (unsigned long long)registration->identity.size, sha256_hex,
	       registration->layout_record_count);

	for (index = 0; index < registration->layout_record_count; index++) {
		const struct nacc_manifest_layout_record *record =
			&registration->layout_records[index];

		printk(KERN_ERR "[Linux]: nacc manifest layout cid=%lx pid=%lu record=%u role=%s phdr=%u page_offset=%llx page_size=%llx flags_raw=%x\n",
		       cid, pid, index,
		       nacc_manifest_object_role_name(record->role),
		       record->phdr_index,
		       (unsigned long long)record->page_offset,
		       (unsigned long long)record->page_size,
		       record->flags_raw);
	}
}

static void nacc_report_registered_manifest_layout(unsigned long cid,
						   const char *tag)
{
	struct nacc_manifest_registration registration;
	unsigned long root_pgd_pa;
	u32 index;

	if (!cid || !current->mm || !current->mm->pgd)
		return;

	if (!nacc_lookup_manifest_registration(cid, &registration))
		return;
	if (!registration.layout_record_count)
		return;

	root_pgd_pa = virt_to_phys(current->mm->pgd);

	printk(KERN_ERR "[Linux]: manifest layout dispatch source=register mm=%px root=%lx cid=%lx tag=%s path=%s records=%u note=manifest PT_LOAD transport via existing startup-range ABI\n",
	       current->mm, root_pgd_pa, cid, tag,
	       registration.identity.path, registration.layout_record_count);

	for (index = 0; index < registration.layout_record_count; index++) {
		const struct nacc_manifest_layout_record *record =
			&registration.layout_records[index];
		int ret;

		printk(KERN_ERR "[Linux]: manifest layout dispatch source=register mm=%px root=%lx cid=%lx tag=%s record=%u role=%s phdr=%u page_offset=%llx page_size=%llx flags_raw=%x\n",
		       current->mm, root_pgd_pa, cid, tag, index,
		       nacc_manifest_object_role_name(record->role),
		       record->phdr_index,
		       (unsigned long long)record->page_offset,
		       (unsigned long long)record->page_size,
		       record->flags_raw);

		ret = nacc_startup_audit_range_sbi(root_pgd_pa, cid, record->role,
						   record->page_offset,
						   record->page_size,
						   record->phdr_index);
		if (ret)
			printk(KERN_ERR "[Linux]: manifest layout dispatch failed mm=%px root=%lx cid=%lx tag=%s record=%u role=%s phdr=%u\n",
			       current->mm, root_pgd_pa, cid, tag, index,
			       nacc_manifest_object_role_name(record->role),
			       record->phdr_index);
	}
}

static unsigned long nacc_fixed_agent_base(void)
{
    if (TASK_SIZE <= NACC_AGENT_SLOT_SIZE + NACC_AGENT_TOP_GAP)
        return 0;

    return TASK_SIZE - NACC_AGENT_TOP_GAP - NACC_AGENT_SLOT_SIZE;
}

static void nacc_activate_current_mm(const char *tag)
{
    unsigned long old_state;

    if (!current->mm)
        return;

    old_state = nacc_mm_state(current->mm);

    if (!(old_state & NACC_MM_ACTIVE)) {
        nacc_mm_set_state(current->mm, NACC_MM_ACTIVE);
        printk(KERN_ERR "[Linux]: activate NaCC mm before SBI handoff (%s), mm=%px state %lx -> %lx\n",
	       tag, current->mm, old_state, nacc_mm_state(current->mm));
    }
}

static void nacc_fail_fork_child_attach(const char *reason, long err,
                                        unsigned long pid,
                                        unsigned long cid)
{
    unsigned long mm_state = current->mm ? nacc_mm_state(current->mm) : 0;

    printk(KERN_ERR "[Linux]: fatal fork child attach failure: reason=%s err=%ld"
           " pid=%lu pid_vnr=%d tgid_vnr=%d cid=%lx mm=%px flag=%lx mm_state=%lx\n",
           reason, err, pid, task_pid_vnr(current), task_tgid_vnr(current), cid,
           current->mm, current->thread.nacc_flag, mm_state);

    /*
     * Do not leave the task in a half-attached NACC_FORKED state, otherwise
     * later notify-resume hooks may retry attach and drift further.
     */
    current->thread.nacc_flag = 0;
    force_exit_sig(SIGKILL);
}

static inline bool nacc_trace_mmap_syscall(void)
{
	return current->mm &&
	       (nacc_mm_is_active(current->mm) || nacc_thread_is_inited());
}

static void nacc_log_sys_mmap(const char *tag, unsigned long addr,
			      unsigned long len, unsigned long prot,
			      unsigned long flags, unsigned long fd,
			      off_t offset, unsigned long page_shift_offset,
			      long ret)
{
	if (!nacc_trace_mmap_syscall())
		return;

	printk(KERN_ERR "[Linux]: %s pid=%d mm=%px flag=%lx mm_state=%lx "
	       "addr=%lx len=%lx prot=%lx flags=%lx fd=%lx offset=%llx "
	       "shift=%lu ret=%ld\n",
	       tag, current->pid, current->mm, current->thread.nacc_flag,
	       nacc_mm_state(current->mm), addr, len, prot, flags, fd,
	       (unsigned long long)offset, page_shift_offset, ret);
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

    printk(KERN_ERR "[Linux]: reserved fixed NACC agent slot (%s): [%lx, %lx), active agent range [%lx, %lx), mm state unchanged=%lx\n",
           tag, virt_agent, virt_end, virt_agent, virt_agent + NACC_AGENT_MEM_SIZE,
           nacc_mm_state(mm));

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

    nacc_activate_current_mm(tag);
    if (nacc_region_sync_mm(current->mm, NACC_REGION_SYNC_REASON_INVOKE))
        printk(KERN_ERR "[Linux]: %s region sync failed for mm=%px\n",
               tag, current->mm);
    nacc_report_startup_elf_coords(current->mm, current->thread.nacc_cid,
                                   tag);
    nacc_report_registered_manifest_layout(current->thread.nacc_cid, tag);

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
	long ret;

	nacc_log_sys_mmap("riscv_sys_mmap: enter", addr, len, prot, flags, fd,
			  offset, page_shift_offset, 0);

	if (unlikely(offset & (~PAGE_MASK >> page_shift_offset))) {
		nacc_log_sys_mmap("riscv_sys_mmap: bad offset", addr, len, prot,
				  flags, fd, offset, page_shift_offset,
				  -EINVAL);
		return -EINVAL;
	}

	ret = ksys_mmap_pgoff(addr, len, prot, flags, fd,
			     offset >> (PAGE_SHIFT - page_shift_offset));
	nacc_log_sys_mmap("riscv_sys_mmap: return", addr, len, prot, flags, fd,
			  offset, page_shift_offset, ret);
	return ret;
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

void nacc_exec(void)
{
    unsigned long pid = current->pid;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);
    struct sbiret ret;

    /*
     * Exec attach is shared by same-PID re-exec and fork+exec after the
     * fresh exec mm has been built by Linux:
     * - install a fresh VM_NACC VMA for the new mm
     * - hand the new user pt_regs to OpenSBI
     * Trap-context refresh inside agent/OpenSBI is handled separately.
     */
    printk(KERN_ERR "[Linux]: NACC_EXEC preparing minimal reattach path.\n");

    if (nacc_insert_agent_vma(&virt_agent, "nacc_exec"))
        return;

    printk(KERN_ERR "[Linux]: nacc_exec using virt_agent %lx\n", virt_agent);

    /*
     * Re-exec now follows the same "non-returning" shape as nacc_invoke():
     * OpenSBI enters the agent and the agent returns directly to userspace.
     * Set INITED before the SBI transition so later kernel entries don't keep
     * seeing the transient REEXEC flag forever.
     */
    nacc_activate_current_mm("nacc_exec");
    if (nacc_region_sync_mm(current->mm, NACC_REGION_SYNC_REASON_EXEC))
        printk(KERN_ERR "[Linux]: nacc_exec region sync failed for mm=%px\n",
               current->mm);
    nacc_report_startup_elf_coords(current->mm, current->thread.nacc_cid,
                                   "nacc_exec");
    nacc_report_registered_manifest_layout(current->thread.nacc_cid,
                                           "nacc_exec");
    current->thread.nacc_flag = NACC_INITED;

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REEXEC, virt_agent, pid,
                    (unsigned long) regs, 0, 0, 0);

    if (ret.error) {
        current->thread.nacc_flag = NACC_EXEC;
        printk(KERN_ERR "[Linux]: nacc_exec SBI returned unexpectedly with error %ld\n",
               ret.error);
    }
}

void nacc_invoke_child(void)
{
    /*
     * For fork + exec cases only.
     * Linux already built the fresh child exec mm using secure non-leaf PTPs.
     * We only need to:
     * 1. Register child PID with parent's CID (done in OpenSBI)
     * 2. Let OpenSBI validate that secure user PTP build and refresh metadata
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

    /* Call into OpenSBI to register child, validate secure user PTPs, and map agent.
     * We pass the cid explicitly to allow OpenSBI to register this child properly.
     * The remaining args are unused since we don't jump into agent. */
    nacc_activate_current_mm("nacc_invoke_child");
    if (nacc_region_sync_mm(current->mm, NACC_REGION_SYNC_REASON_EXEC))
        printk(KERN_ERR "[Linux]: nacc_invoke_child region sync failed for mm=%px\n",
               current->mm);
    nacc_report_startup_elf_coords(current->mm, cid,
                                   "nacc_invoke_child");
    nacc_report_registered_manifest_layout(cid, "nacc_invoke_child");
    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE_CHILD, virt_agent, pid,
              cid, 0, 0, 0);

    /*
     * Mark as INITED only after OpenSBI re-attach completes and NACC_STATE
     * has been switched to LINUX in M-mode.
     */
    current->thread.nacc_flag = NACC_INITED;

    printk(KERN_ERR "[Linux]: nacc_invoke_child done, child continues in Linux.\n");
}

void nacc_attach_forked_child_if_needed(void)
{
    unsigned long pid;
    unsigned long cid;
    unsigned long virt_agent = 0;
    unsigned long user_pt_regs = 0;
    int vma_ret;
    struct sbiret ret;

    if (current->thread.nacc_flag != NACC_FORKED)
        return;

    if (!current->mm) {
        printk(KERN_ERR "[Linux]: skip fork child attach without mm, pid=%d flag=%lx\n",
               current->pid, current->thread.nacc_flag);
        nacc_fail_fork_child_attach("missing-mm", -EINVAL, current->pid,
                                    current->thread.nacc_cid);
        return;
    }

    pid = current->pid;
    cid = current->thread.nacc_cid;
    user_pt_regs = (unsigned long)task_pt_regs(current);

    printk(KERN_ERR "[Linux]: first user return attaches fork child, pid=%lu cid=%lx nacc_flag=%lx mm=%px regs=%px state=%lx epc=%lx sp=%lx ra=%lx tp=%lx a0=%lx a1=%lx a2=%lx a3=%lx a0_is_zero=%s\n",
           pid, cid, current->thread.nacc_flag, current->mm,
           (void *)user_pt_regs, nacc_mm_state(current->mm),
           task_pt_regs(current)->epc, task_pt_regs(current)->sp,
           task_pt_regs(current)->ra, task_pt_regs(current)->tp,
           task_pt_regs(current)->a0, task_pt_regs(current)->a1,
           task_pt_regs(current)->a2, task_pt_regs(current)->a3,
           task_pt_regs(current)->a0 == 0 ? "yes" : "no");

    vma_ret = nacc_insert_agent_vma(&virt_agent, "nacc_attach_forked_child");
    if (vma_ret) {
        printk(KERN_ERR "[Linux]: failed to insert VM_NACC slot for fork child pid=%lu\n",
               pid);
        nacc_fail_fork_child_attach("insert-agent-vma", vma_ret, pid, cid);
        return;
    }

    nacc_activate_current_mm("nacc_attach_forked_child");
    if (nacc_region_sync_mm(current->mm, NACC_REGION_SYNC_REASON_FORK))
        printk(KERN_ERR "[Linux]: fork child attach region sync failed for mm=%px\n",
               current->mm);
    /*
     * Child attach now follows the same non-returning lightweight agent shape
     * as exec attach: OpenSBI enters the agent and the agent returns directly
     * to userspace after refreshing the trap contract for this child.
     */
    current->thread.nacc_flag = NACC_INITED;

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ATTACH_FORKED_CHILD,
                    virt_agent, pid, cid, user_pt_regs, 0, 0);
    if (ret.error) {
        current->thread.nacc_flag = NACC_FORKED;
        printk(KERN_ERR "[Linux]: fork child attach SBI failed, pid=%lu cid=%lx err=%ld\n",
               pid, cid, ret.error);
        nacc_fail_fork_child_attach("sbi-attach", ret.error, pid, cid);
        return;
    }

    current->thread.nacc_flag = NACC_FORKED;
    printk(KERN_ERR "[Linux]: fork child attach unexpectedly returned, pid=%lu cid=%lx virt_agent=%lx\n",
           pid, cid, virt_agent);
    nacc_fail_fork_child_attach("sbi-attach-return", -EIO, pid, cid);
}

void nacc_register_forked_child_pid(unsigned long child_pid)
{
    unsigned long cid = current->thread.nacc_cid;
    struct sbiret ret;

    if (!(current->thread.nacc_flag & NACC_INITED))
        return;

    if (!cid || !child_pid) {
        printk(KERN_ERR "[Linux]: skip fork child pid registration: parent pid=%d child_pid=%lu cid=%lx flag=%lx\n",
               current->pid, child_pid, cid, current->thread.nacc_flag);
        return;
    }

    printk(KERN_ERR "[Linux]: register fork child pid early, parent pid=%d child_pid=%lu cid=%lx\n",
           current->pid, child_pid, cid);

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, child_pid,
                    0, 0, 0, 0);
    if (ret.error) {
        printk(KERN_ERR "[Linux]: early fork child pid registration failed: parent pid=%d child_pid=%lu cid=%lx err=%ld val=%ld\n",
               current->pid, child_pid, cid, ret.error, ret.value);
    }
}

void nacc_set_ptes_sbi(unsigned long ptep_pa, unsigned long pteval,
		       unsigned int nr, unsigned long start_va,
		       unsigned long root_pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_SET_PTES, ptep_pa,
			pteval, nr, start_va, root_pgd_pa, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_set_ptes_sbi failed: ptep_pa=%lx pteval=%lx nr=%u start_va=%lx root=%lx err=%ld val=%ld\n",
		       ptep_pa, pteval, nr, start_va, root_pgd_pa,
		       ret.error, ret.value);
	}
}

void nacc_wrprotect_ptes_sbi(unsigned long ptep_pa, unsigned int nr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_WRPROTECT_PTES, ptep_pa,
			nr, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_wrprotect_ptes_sbi failed: ptep_pa=%lx nr=%u err=%ld val=%ld\n",
		       ptep_pa, nr, ret.error, ret.value);
	}
}

int nacc_tag_root_sbi(unsigned long pgd_pa, unsigned long cid)
{
	struct sbiret ret;

	if (!pgd_pa || !cid)
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_TAG_ROOT, pgd_pa,
			cid, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_tag_root_sbi failed: pgd_pa=%lx cid=%lx err=%ld val=%ld\n",
		       pgd_pa, cid, ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

void nacc_retire_root_sbi(unsigned long pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RETIRE_ROOT, pgd_pa,
			0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_retire_root_sbi failed: pgd_pa=%lx err=%ld val=%ld\n",
		       pgd_pa, ret.error, ret.value);
	}
}

SYSCALL_DEFINE6(nacc_register, unsigned long, cid,
		const char __user *, manifest_path,
		const u8 __user *, manifest_sha256,
		u64, manifest_size,
		const struct nacc_manifest_layout_record __user *,
		manifest_layout,
		u64, manifest_layout_record_count)
{
	struct nacc_manifest_registration registration;
	unsigned long pid;
	struct sbiret ret;
	int manifest_ret = 0;
	int layout_ret = 0;
	bool manifest_present = false;

	printk(KERN_ERR "[Linux] register a new NACC process.\n");

	/*
	 * Mark the current process as nacc process here.
	 * However, as the preparation state.
	 */
	current->thread.nacc_flag = NACC_PREPARE;
	current->thread.nacc_cid = cid;

	pid = current->pid;
	printk(KERN_ERR "[Linux]: container id is %lx.\n", cid);
	memset(&registration, 0, sizeof(registration));

	if (!manifest_path && !manifest_sha256 && !manifest_size &&
	    !manifest_layout && !manifest_layout_record_count) {
		manifest_present = false;
	} else if (!manifest_path || !manifest_sha256) {
		printk(KERN_ERR "[Linux]: nacc manifest payload incomplete for cid=%lx pid=%lu path_ptr=%px sha_ptr=%px size=%llu layout_ptr=%px layout_records=%llu; continuing with cid-only registration\n",
		       cid, pid, manifest_path, manifest_sha256,
		       (unsigned long long)manifest_size, manifest_layout,
		       (unsigned long long)manifest_layout_record_count);
	} else {
		manifest_ret = nacc_copy_manifest_identity_from_user(
			&registration.identity, manifest_path,
			manifest_sha256, manifest_size);
		if (manifest_ret) {
			printk(KERN_ERR "[Linux]: nacc manifest payload ignored for cid=%lx pid=%lu err=%d size=%llu layout_records=%llu; continuing with cid-only registration\n",
			       cid, pid, manifest_ret,
			       (unsigned long long)manifest_size,
			       (unsigned long long)manifest_layout_record_count);
		} else {
			manifest_present = true;
			if (!manifest_layout && !manifest_layout_record_count) {
				registration.layout_record_count = 0;
			} else if (!manifest_layout ||
				   !manifest_layout_record_count) {
				printk(KERN_ERR "[Linux]: nacc manifest layout payload incomplete for cid=%lx pid=%lu layout_ptr=%px layout_records=%llu; keeping identity only\n",
				       cid, pid, manifest_layout,
				       (unsigned long long)
				       manifest_layout_record_count);
			} else {
				layout_ret = nacc_copy_manifest_layout_from_user(
					&registration, manifest_layout,
					manifest_layout_record_count);
				if (layout_ret) {
					printk(KERN_ERR "[Linux]: nacc manifest layout payload ignored for cid=%lx pid=%lu err=%d layout_records=%llu; keeping identity only\n",
					       cid, pid, layout_ret,
					       (unsigned long long)
					       manifest_layout_record_count);
				}
			}
		}
	}

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, pid, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc register SBI failed cid=%lx pid=%lu err=%ld val=%ld\n",
		       cid, pid, ret.error, ret.value);
	} else if (manifest_present) {
		nacc_store_manifest_registration(cid, &registration);
		nacc_log_manifest_registration(cid, pid, &registration);
	}

	printk(KERN_ERR "[Linux]: GO BACK TO RUNC.\n");

	return 0;
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
