// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/instruction_pointer.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/bitops.h>

#include <asm/word-at-a-time.h>

#ifdef NACC
static __always_inline bool nacc_strnlen_user_scope_window(
	const char __user *src, unsigned long max,
	unsigned long *scope_va, unsigned long *scope_len)
{
	const unsigned long word_bytes = sizeof(unsigned long);
	const unsigned long word_mask = word_bytes - 1;
	unsigned long align = word_mask & (unsigned long)src;
	unsigned long va = (unsigned long)src - align;
	unsigned long bytes = max;

	if (bytes > ~0UL - align)
		return false;
	bytes += align;
	if (!bytes || bytes > ~0UL - word_mask)
		return false;

	bytes = (bytes + word_mask) & ~word_mask;
	if (va > ~0UL - bytes)
		return false;

	*scope_va = va;
	*scope_len = bytes;
	return true;
}
#endif

/*
 * Do a strnlen, return length of string *with* final '\0'.
 * 'count' is the user-supplied count, while 'max' is the
 * address space maximum.
 *
 * Return 0 for exceptions (which includes hitting the address
 * space maximum), or 'count+1' if hitting the user-supplied
 * maximum count.
 *
 * NOTE! We can sometimes overshoot the user-supplied maximum
 * if it fits in a aligned 'long'. The caller needs to check
 * the return value against "> max".
 */
static __always_inline long do_strnlen_user(const char __user *src, unsigned long count, unsigned long max)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	unsigned long align, res = 0;
	unsigned long c;

	/*
	 * Do everything aligned. But that means that we
	 * need to also expand the maximum..
	 */
	align = (sizeof(unsigned long) - 1) & (unsigned long)src;
	src -= align;
	max += align;

	unsafe_get_user(c, (unsigned long __user *)src, efault);
	c |= aligned_byte_mask(align);

	for (;;) {
		unsigned long data;
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			return res + find_zero(data) + 1 - align;
		}
		res += sizeof(unsigned long);
		/* We already handled 'unsigned long' bytes. Did we do it all ? */
		if (unlikely(max <= sizeof(unsigned long)))
			break;
		max -= sizeof(unsigned long);
		unsafe_get_user(c, (unsigned long __user *)(src+res), efault);
	}
	res -= align;

	/*
	 * Uhhuh. We hit 'max'. But was that the user-specified maximum
	 * too? If so, return the marker for "too long".
	 */
	if (res >= count)
		return count+1;

	/*
	 * Nope: we hit the address space limit, and we still had more
	 * characters the caller would have wanted. That's 0.
	 */
efault:
	return 0;
}

/**
 * strnlen_user: - Get the size of a user string INCLUDING final NUL.
 * @str: The string to measure.
 * @count: Maximum count (including NUL character)
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * If the string is too long, returns a number larger than @count. User
 * has to check the return value against "> count".
 * On exception (or invalid count), returns 0.
 *
 * NOTE! You should basically never use this function. There is
 * almost never any valid case for using the length of a user space
 * string, since the string can be changed at any time by other
 * threads. Use "strncpy_from_user()" instead to get a stable copy
 * of the string.
 */
long strnlen_user(const char __user *str, long count)
{
	unsigned long max_addr, src_addr;

	if (unlikely(count <= 0))
		return 0;

	if (can_do_masked_user_access()) {
		long retval;
#ifdef NACC
		unsigned long nacc_scope_va;
		unsigned long nacc_scope_len;
#endif

		str = masked_user_access_begin(str);
#ifdef NACC
		if (!nacc_strnlen_user_scope_window(str, count,
						    &nacc_scope_va,
						    &nacc_scope_len)) {
			user_read_access_end();
			return 0;
		}
		if (!nacc_uaccess_scope_begin(NACC_UACCESS_SCOPE_STRING_READ,
					      NACC_UACCESS_SCOPE_DIR_FROM_USER,
					      nacc_scope_va, nacc_scope_len,
					      _RET_IP_)) {
			user_read_access_end();
			return 0;
		}
#endif
		retval = do_strnlen_user(str, count, count);
#ifdef NACC
		if (!nacc_uaccess_scope_end(NACC_UACCESS_SCOPE_STRING_READ,
					    NACC_UACCESS_SCOPE_DIR_FROM_USER,
					    nacc_scope_va, nacc_scope_len,
					    retval))
			retval = 0;
#endif
		user_read_access_end();
		return retval;
	}

	max_addr = TASK_SIZE_MAX;
	src_addr = (unsigned long)untagged_addr(str);
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		long retval;
#ifdef NACC
		unsigned long nacc_scope_va;
		unsigned long nacc_scope_len;
#endif

		/*
		 * Truncate 'max' to the user-specified limit, so that
		 * we only have one limit we need to check in the loop
		 */
		if (max > count)
			max = count;

		if (user_read_access_begin(str, max)) {
#ifdef NACC
			if (!nacc_strnlen_user_scope_window(str, max,
							    &nacc_scope_va,
							    &nacc_scope_len)) {
				user_read_access_end();
				return 0;
			}
			if (!nacc_uaccess_scope_begin(NACC_UACCESS_SCOPE_STRING_READ,
						      NACC_UACCESS_SCOPE_DIR_FROM_USER,
						      nacc_scope_va,
						      nacc_scope_len,
						      _RET_IP_)) {
				user_read_access_end();
				return 0;
			}
#endif
			retval = do_strnlen_user(str, count, max);
#ifdef NACC
			if (!nacc_uaccess_scope_end(NACC_UACCESS_SCOPE_STRING_READ,
						    NACC_UACCESS_SCOPE_DIR_FROM_USER,
						    nacc_scope_va,
						    nacc_scope_len,
						    retval))
				retval = 0;
#endif
			user_read_access_end();
			return retval;
		}
	}
	return 0;
}
EXPORT_SYMBOL(strnlen_user);
