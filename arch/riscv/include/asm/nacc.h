#ifndef _ASM_RISCV_NACC_H
#define _ASM_RISCV_NACC_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/sched.h>
#define NACC_RECLAIM_LIST_SIZE 511

struct mm_struct;
struct ptdesc;
struct vm_area_struct;

struct nacc_reclaim_list {
	unsigned long pfns[NACC_RECLAIM_LIST_SIZE];
	unsigned long count;
};

/* another macro for nacc_flag in nacc->thread field */
#define NACC_PREPARE     0b001
#define NACC_INITED      0b010

#define NACC_MM_ACTIVE		0x1UL
#define NACC_MM_ROOT_TAGGED	0x2UL

enum nacc_private_data_path_category {
	NACC_PD_PATH_UNKNOWN = 0,
	NACC_PD_PATH_USER_BUFFER_READ = 1,
	NACC_PD_PATH_USER_BUFFER_WRITE = 2,
	NACC_PD_PATH_FILE_PATH = 3,
	NACC_PD_PATH_PIPE = 4,
	NACC_PD_PATH_FORK_EXEC = 5,
	NACC_PD_PATH_MAPPING_UPDATE = 6,
	NACC_PD_PATH_EXIT_TEARDOWN = 7,
	NACC_PD_PATH_SHARED_MEMORY = 8,
};

enum nacc_private_data_uaccess_direction {
	NACC_PD_UACCESS_UNKNOWN = 0,
	NACC_PD_UACCESS_FROM_USER = 1,
	NACC_PD_UACCESS_TO_USER = 2,
};

enum nacc_uaccess_tx_api_kind {
	NACC_UACCESS_TX_COPY_FROM_USER = 1,
	NACC_UACCESS_TX_COPY_TO_USER = 2,
	NACC_UACCESS_TX_GET_USER = 3,
	NACC_UACCESS_TX_PUT_USER = 4,
	NACC_UACCESS_TX_CLEAR_USER = 5,
};

enum nacc_uaccess_tx_direction {
	NACC_UACCESS_TX_DIR_UNKNOWN = 0,
	NACC_UACCESS_TX_DIR_FROM_USER = 1,
	NACC_UACCESS_TX_DIR_TO_USER = 2,
	NACC_UACCESS_TX_DIR_ZERO_TO_USER = 3,
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

void add_to_reclaim_list(unsigned long pfn);
void flush_reclaim_list(void);

unsigned long nacc_mm_state(struct mm_struct *mm);
void nacc_mm_set_state(struct mm_struct *mm, unsigned long mask);
bool nacc_mm_is_active(struct mm_struct *mm);
int nacc_detach_user_leaf_pages(struct mm_struct *mm, const char *tag);

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
int nacc_retire_private_pfn_sbi(unsigned long pfn);
void nacc_private_data_syscall_enter(unsigned long syscall_nr,
				     unsigned long path_category,
				     const char *syscall_name);
void nacc_private_data_syscall_exit(unsigned long syscall_nr,
				    unsigned long path_category);
void nacc_private_data_uaccess_enter(unsigned long direction,
				     unsigned long caller_pc,
				     unsigned long user_va,
				     unsigned long bytes);
void nacc_private_data_uaccess_exit(void);
u64 nacc_uaccess_tx_begin(enum nacc_uaccess_tx_api_kind api_kind,
			  enum nacc_uaccess_tx_direction direction,
			  unsigned long caller_pc,
			  unsigned long user_va,
			  unsigned long bytes);
void nacc_uaccess_tx_end(u64 tx_id,
			 enum nacc_uaccess_tx_api_kind api_kind,
			 enum nacc_uaccess_tx_direction direction,
			 unsigned long caller_pc,
			 unsigned long user_va,
			 unsigned long bytes,
			 long result);
#endif

#endif /* _ASM_RISCV_NACC_H */
