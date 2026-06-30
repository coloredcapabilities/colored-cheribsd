/*
 * Flat bitmap otype allocator.
 *
 * Fixed memory: sizeof(struct) + num_bits/8 bytes (~256KB for 2M otypes).
 * Uses bitstring.h for safe bit manipulation.
 *
 * free_many uses raw uint64_t to match sealing bitmap format.
 * Thread-safe via atomic_flag spinlock.
 */

#include <sys/param.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/bitstring.h>
#include <stdint.h>
#include <stdatomic.h>

#include "bitmap_otype_allocator.h"

/* 
 * Verify bitstring size and uint64 size are the same, as this
 * is required for free_many to work properly 
 */
_Static_assert(sizeof(bitstr_t) == sizeof(uint64_t),
    "bitmap_otype_allocator assumes 64-bit bitstr_t");

/* Uncomment for debug print in free_many */
// #define BITMAP_DEBUG

#ifdef BITMAP_DEBUG
	#include <unistd.h>
#endif

static inline void
ba_lock(struct bitmap_otype_allocator *ba)
{
	while (atomic_flag_test_and_set(&ba->lock)) {
		/* spin */
	}
}

static inline void
ba_unlock(struct bitmap_otype_allocator *ba)
{
	atomic_flag_clear(&ba->lock);
}

int
bitmap_otype_alloc(struct bitmap_otype_allocator *ba)
{
	/* We cannot allocate without a bitmap */
	if (ba->bitmap == NULL)
		return (-1);

	ba_lock(ba);

	int pos;

	/* Fast path: if hint points to a free bit, take it directly
	   without scanning. Common case for sequential allocations. */
	if (!bit_test(ba->bitmap, ba->hint)) {
		pos = ba->hint;
	} else {
		/* Slow path: scan for first free bit from hint to end */
		bit_ffc_at(ba->bitmap, ba->hint, ba->num_bits, &pos);
		if (pos == -1) {
			/* Wrap around and search from [0, hint) */
			bit_ffc_at(ba->bitmap, 0, ba->hint, &pos);
			if (pos == -1) {
				ba_unlock(ba);
				return (-1);
			}
		}
	}

	/* Set the bit at the found index to 1 */
	bit_set(ba->bitmap, pos);
	/* Increase the number of allocated otypes */
	ba->busy++;
	/* Update the hint to one after the found index, meaning we 
	walk the indices of the bitmap consecutively */
	ba->hint = (u_int)pos + 1;
	/* If the hint is bigger than total number of bitmap positions it wraps around 
	and starts from the first position of the bitmap again */
	if (ba->hint >= ba->num_bits)
		ba->hint = 0;

	ba_unlock(ba);

	/* Convert the bitmap index into an actual otype by adding low 
	and return that otype */
	return (pos + (int)ba->low);
}

int
bitmap_otype_alloc_specific(struct bitmap_otype_allocator *ba, u_int item)
{
	/* We cannot allocate an item smaller than low or higher than high */
	if (item < ba->low || item > ba->high)
		return (-1);

	ba_lock(ba);

	/* Convert the item to an offset in the bitmap */
	u_int pos = item - ba->low;
	/* Test if bit at the offset is already allocated */
	if (bit_test(ba->bitmap, pos)) {
		ba_unlock(ba);
		return (-1);
	}
	
	/* Set the bit at offset to 1 */
	bit_set(ba->bitmap, pos);
	/* Increase amount of allocated otypes */
	ba->busy++;

	ba_unlock(ba);

	/* Return the item itself if it was free */
	return (int)item;
}

/*
 * Free otypes in bulk based on the sealing bitmap from the kernel.
 * Callers must ensure that sealing_bitmap covers at least [low..high],
 * i.e., word indices low/64 through high/64 are valid reads.
 */
void
bitmap_otype_free_many(struct bitmap_otype_allocator *ba, uint64_t *sealing_bitmap)
{
#ifdef BITMAP_DEBUG
    write(2, "Entry free many\n", 16);
#endif
	ba_lock(ba);

	// Number of 64 words needed to represent our full bitmap size
	u_int num_words = (ba->num_bits + 63) / 64;
	// Word offset in the bitmap the sealing bitmap starts at
	u_int sb_start_word = ba->low / 64;
	// Bit offset in the bitmap the sealing bitmap starts at
	u_int sb_start_bit = ba->low % 64;
	/*
	* Convert bitmap pointer to uint64, so we can use 64 word processing
	* with the sealing bitmap
	*/
	uint64_t *bm = (uint64_t *)ba->bitmap;
	// Count of bits freed to adjust ba->busy later
	u_int freed = 0;
	// Track if a new hint value was set
	bool hint_set = false;

	// Iterate over the bitmap in 64 word processing manner
	for (u_int i = 0; i < num_words; i++) {
		/*
		 * Our bitmap position 0 corresponds to otype 'low', which is
		 * bit 'low' in the sealing bitmap. Since low may not be
		 * word-aligned, we shift right to align the sealing bits
		 * with our bitmap word.
		 */
		uint64_t sealed = sealing_bitmap[sb_start_word + i] >> sb_start_bit;
		/*
		 * The shift above only gives us the lower (64 - sb_start_bit)
		 * bits. We need the remaining upper sb_start_bit bits from
		 * the next sealing bitmap word to complete our aligned word.
		 * Only do this if there IS a bit offset and the next word is
		 * within bounds.
		 */
		if (sb_start_bit != 0 && (sb_start_word + i + 1) <= ba->high / 64)
			sealed |= sealing_bitmap[sb_start_word + i + 1] << (64 - sb_start_bit);

		// If sealed is only 0's there is nothing to free for this word
		if (sealed == 0)
			continue;

		/*
		 * Count bits that are both sealed (to be freed) AND currently
		 * allocated in our bitmap. This gives the actual number of
		 * otypes freed, ignoring sealing bits for already-free slots.
		 */
		freed += __builtin_popcountll(sealed & bm[i]);
		/*
		 * Clear the sealed bits in our bitmap. ~sealed inverts to a
		 * mask of bits to keep, AND preserves only those effectively
		 * setting all sealed positions to 0 (free).
		 */
		bm[i] &= ~sealed;

		/*
		 * Set hint to the start of the first word that had freed bits.
		 * This way the next allocation starts searching near recently
		 * freed otypes rather than scanning from the beginning.
		 */
		if (!hint_set) {
			ba->hint = i * 64;
			hint_set = true;
		}
	}

	/* Protect against a sealing bitmap with more bits to free than allocated */
	if (freed > ba->busy) {
		int count;
		bit_count(ba->bitmap, 0, ba->num_bits, &count);
		ba->busy = (u_int)count;
	}
	else {
		ba->busy -= freed;
	}

	/*
	* If the hint has not been updated at all just set hint to 0 to start to search
	* from the start of the bitmap.
	*/
	if (!hint_set)
		ba->hint = 0;

	ba_unlock(ba);
#ifdef BITMAP_DEBUG
	write(2, "Exit free many\n", 15);
#endif
}

size_t
bitmap_otype_mem_usage(struct bitmap_otype_allocator *ba)
{
	return sizeof(*ba) + bitstr_size(ba->num_bits);
}
