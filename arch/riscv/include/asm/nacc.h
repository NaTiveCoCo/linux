#ifndef _ASM_RISCV_NACC_H
#define _ASM_RISCV_NACC_H

#ifndef __ASSEMBLY__
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/sched.h>
#define NACC_RECLAIM_LIST_SIZE 511

struct mm_struct;
struct page;
struct ptdesc;
struct vm_area_struct;

struct nacc_reclaim_list {
	unsigned long pfns[NACC_RECLAIM_LIST_SIZE];
	unsigned long count;
};

#ifdef NACC_LOG_DEBUG
#define nacc_debug(fmt, ...) printk(KERN_ERR fmt, ##__VA_ARGS__)
#define nacc_debug_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ERR fmt, ##__VA_ARGS__)
#else
#define nacc_debug(fmt, ...) no_printk(KERN_ERR fmt, ##__VA_ARGS__)
#define nacc_debug_ratelimited(fmt, ...) \
	no_printk(KERN_ERR fmt, ##__VA_ARGS__)
#endif

/* another macro for nacc_flag in nacc->thread field */
#define NACC_PREPARE     0b001
#define NACC_INITED      0b010

#define NACC_MM_ACTIVE		0x1UL
#define NACC_MM_ROOT_TAGGED	0x2UL

enum nacc_uaccess_scope_class {
	NACC_UACCESS_SCOPE_CLASS_UNKNOWN = 0,
	NACC_UACCESS_SCOPE_STRING_READ = 1,
};

enum nacc_uaccess_scope_direction {
	NACC_UACCESS_SCOPE_DIR_UNKNOWN = 0,
	NACC_UACCESS_SCOPE_DIR_FROM_USER = 1,
	NACC_UACCESS_SCOPE_DIR_TO_USER = 2,
};

#define NACC_UACCESS_STRING_READ_DESC_VERSION	1UL
#define NACC_UACCESS_STRING_READ_NO_NUL		(~0UL)

enum nacc_uaccess_string_read_op {
	NACC_UACCESS_STRING_READ_OP_UNKNOWN = 0,
	NACC_UACCESS_STRING_READ_OP_COPY_CSTR = 1,
	NACC_UACCESS_STRING_READ_OP_MEASURE_CSTR = 2,
};

struct nacc_uaccess_string_read_desc {
	unsigned long version;
	unsigned long op;
	unsigned long flags;
	unsigned long buffer_va;
	unsigned long buffer_bytes;
	unsigned long count;
	unsigned long scanned_bytes;
	unsigned long copied_bytes;
	unsigned long nul_index;
	unsigned long private_bytes;
	unsigned long caller_pc;
};

/* 
 * The agent has already been initialized, and the new child process is forked.
 * This flag is set in the child process.
 */
#define NACC_FORKED      0b1000

/*
 * Exec rebuild state for an already NaCC-protected task.
 * Covers both same-PID re-exec and fork+exec before final re-attach.
 */
#define NACC_EXEC        0b10000

#define NACC_PTP_PFN_BASE  0x1b0000
#define NACC_PTP_PFN_END   0x1c0000

#define NACC_USER_VPN2_PROTECTED_SLOTS 256UL
#define NACC_USER_VPN2_SLOT_SIZE       (1UL << 30)
#define NACC_USER_VPN2_PROTECTED_END \
	(NACC_USER_VPN2_PROTECTED_SLOTS * NACC_USER_VPN2_SLOT_SIZE)

enum nacc_update_pte_op {
	NACC_UPDATE_PTE_XCHG_ONE = 1,
	NACC_UPDATE_PTE_TEST_CLEAR_YOUNG_ONE = 2,
};

enum nacc_copy_user_highpage_result {
	NACC_COPY_USER_HIGHPAGE_NOT_HANDLED = 0,
	NACC_COPY_USER_HIGHPAGE_HANDLED = 1,
};

void add_to_reclaim_list(unsigned long pfn);
void flush_reclaim_list(void);

unsigned long nacc_mm_state(struct mm_struct *mm);
void nacc_mm_set_state(struct mm_struct *mm, unsigned long mask);
bool nacc_mm_is_active(struct mm_struct *mm);
int nacc_detach_user_leaf_pages(struct mm_struct *mm, const char *tag);

#ifdef NACC_PROFILE
void nacc_profile_mm_active_enter(void);
void nacc_profile_mm_active_exit(void);
void nacc_profile_root_tag(void);
void nacc_profile_root_retire(void);
void nacc_profile_sys_register(void);
void nacc_profile_fork_child_register(void);
void nacc_profile_unregister_success(void);
void nacc_profile_unregister_fail(void);
void nacc_profile_secure_ptp_queue(unsigned long count);
void nacc_profile_secure_ptp_flush(unsigned long count);
#else
static inline void nacc_profile_mm_active_enter(void) { }
static inline void nacc_profile_mm_active_exit(void) { }
static inline void nacc_profile_root_tag(void) { }
static inline void nacc_profile_root_retire(void) { }
static inline void nacc_profile_sys_register(void) { }
static inline void nacc_profile_fork_child_register(void) { }
static inline void nacc_profile_unregister_success(void) { }
static inline void nacc_profile_unregister_fail(void) { }
static inline void nacc_profile_secure_ptp_queue(unsigned long count) { }
static inline void nacc_profile_secure_ptp_flush(unsigned long count) { }
#endif

static inline bool nacc_thread_is_inited(void)
{
	return !!(current->thread.nacc_flag & NACC_INITED);
}

static inline bool nacc_thread_has_root_l0_lifecycle(void)
{
	unsigned long flag = current->thread.nacc_flag;

	return flag == NACC_PREPARE || flag == NACC_FORKED ||
	       flag == NACC_EXEC || !!(flag & NACC_INITED);
}

static inline bool nacc_private_data_uaccess_active(void)
{
	return current->mm &&
	       current->thread.nacc_cid &&
	       (nacc_thread_is_inited() || nacc_mm_is_active(current->mm));
}

static inline bool nacc_use_secure_pt(struct mm_struct *mm)
{
	/*
	 * Secure page-table handling is needed when:
	 * - the current task already owns secure page tables (fork/COW path)
	 * - an mm has entered the NaCC secure PTP lifecycle, including a
	 *   freshly created exec mm before it becomes current
	 */
	return nacc_thread_is_inited() ||
	       nacc_mm_is_active(mm);
}

static inline bool nacc_pfn_is_secure_ptp(unsigned long pfn)
{
	return pfn >= NACC_PTP_PFN_BASE && pfn < NACC_PTP_PFN_END;
}

static inline bool nacc_mm_root_tagged(struct mm_struct *mm)
{
	return !!(nacc_mm_state(mm) & NACC_MM_ROOT_TAGGED);
}

static inline void nacc_track_secure_ptp_pfn(unsigned long pfn)
{
	if (nacc_pfn_is_secure_ptp(pfn))
		add_to_reclaim_list(pfn);
}

void nacc_invoke(void);
void nacc_exec(void);
void nacc_invoke_child(void);
void nacc_attach_forked_child_if_needed(void);
void nacc_register_forked_child_pid(unsigned long child_pid);
void nacc_unregister_current_pid(void);
int nacc_reserve_agent_slot_mm(struct mm_struct *mm, const char *tag);

void pgtbl_debug(unsigned long pgd);
#ifdef CONFIG_MMU
bool nacc_vma_is_vvar_abi_data(const struct vm_area_struct *vma);
#else
static inline bool nacc_vma_is_vvar_abi_data(const struct vm_area_struct *vma)
{
	(void)vma;
	return false;
}
#endif

int page_nacc_register_ptp(unsigned long pfn, unsigned int level);
void nacc_reclaim_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
			   unsigned int level, const char *tag);

void nacc_set_ptes_sbi(unsigned long ptep_pa, unsigned long pteval,
		       unsigned int nr, unsigned long start_va,
		       unsigned long root_pgd_pa);
void nacc_wrprotect_ptes_sbi(unsigned long ptep_pa, unsigned int nr);
unsigned long nacc_update_pte_sbi(unsigned long op, unsigned long ptep_pa,
				  unsigned long operand, unsigned long start_va,
				  unsigned long root_pgd_pa,
				  unsigned long flags);
int nacc_tag_root_sbi(unsigned long pgd_pa, unsigned long cid);
void nacc_retire_root_sbi(unsigned long pgd_pa);
int nacc_acquire_private_pfn_sbi(unsigned long pfn);
int nacc_release_private_pfn_sbi(unsigned long pfn);
int nacc_retire_private_pfn_sbi(unsigned long pfn);
bool nacc_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma);
bool nacc_uaccess_scope_begin(enum nacc_uaccess_scope_class scope_class,
			      enum nacc_uaccess_scope_direction direction,
			      unsigned long user_va,
			      unsigned long bytes,
			      unsigned long caller_pc);
int nacc_uaccess_string_read_begin(unsigned long user_va,
				   unsigned long bytes,
				   struct nacc_uaccess_string_read_desc *desc);
bool nacc_uaccess_scope_end(enum nacc_uaccess_scope_class scope_class,
			    enum nacc_uaccess_scope_direction direction,
			    unsigned long user_va,
			    unsigned long bytes,
			    long result);
int nacc_private_data_get_user_read(unsigned long user_va,
				    unsigned long bytes,
				    unsigned long *value);
int nacc_private_data_put_user_write(unsigned long user_va,
				     const void *value,
				     unsigned long bytes);
int nacc_private_data_copy_to_user(unsigned long user_va,
				   unsigned long kernel_va,
				   unsigned long bytes,
				   unsigned long caller_pc,
				   unsigned long *left);
int nacc_private_data_copy_from_user(unsigned long kernel_va,
				     unsigned long user_va,
				     unsigned long bytes,
				     unsigned long caller_pc,
				     unsigned long *left);
int nacc_private_data_clear_user(unsigned long user_va,
				 unsigned long bytes,
				 unsigned long caller_pc,
				 unsigned long *left);
#endif

#endif /* _ASM_RISCV_NACC_H */
