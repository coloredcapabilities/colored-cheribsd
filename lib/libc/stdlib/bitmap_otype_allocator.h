/*
 * Flat bitmap otype allocator.
 *
 * Fixed memory: sizeof(struct) + num_bits/8 bytes (~256KB for 2M otypes).
 * Uses bitstring.h for safe bit manipulation.
 */

#ifndef _BITMAP_OTYPE_ALLOCATOR_H
#define _BITMAP_OTYPE_ALLOCATOR_H

#include <sys/types.h>
#include <sys/bitstring.h>
#include <stdint.h>
#include <stdatomic.h>

/*
 * All fields except 'lock' must only be accessed while holding the lock.
 */
struct bitmap_otype_allocator {
	bitstr_t	*bitmap; /* Bitmap to represent free and allocated otypes
						    Free =  0; Allocated = 1
						*/
	u_int		low; /* Lowest possible otype */
	u_int		high; /* Highest possible otype */
	u_int		busy; /* Amount of allocated otypes */
	u_int		num_bits; /* Total count of otypes in the range */
	u_int		hint; /* Hint to the next free otype (bitmap offset) */
	atomic_flag	lock; /* Spinlock for thread safety */
};

int bitmap_otype_alloc(struct bitmap_otype_allocator *ba);
int bitmap_otype_alloc_specific(struct bitmap_otype_allocator *ba, u_int item);
void bitmap_otype_free_many(struct bitmap_otype_allocator *ba, uint64_t *sealing_bitmap);
size_t bitmap_otype_mem_usage(struct bitmap_otype_allocator *ba);

#endif /* _BITMAP_OTYPE_ALLOCATOR_H */
