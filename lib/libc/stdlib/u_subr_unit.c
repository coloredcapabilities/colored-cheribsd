/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2004 Poul-Henning Kamp
 * All rights reserved.
 * 
 * 
 * Colored-Cap modifications: 
 *      Author: Ruben Sturm, Merve Gulmez
 *      Copyright (c) 2025 Ericsson AB 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * Unit number allocation functions.
 *
 * These functions implement a mixed run-length/bitmap management of unit
 * number spaces in a very memory efficient manner.
 *
 * Allocation policy is always lowest free number first.
 *
 * A return value of -1 signals that no more unit numbers are available.
 *
 * There is no cost associated with the range of unitnumbers, so unless
 * the resource really is finite, specify INT_MAX to new_unrhdr() and
 * forget about checking the return value.
 *
 * If a mutex is not provided when the unit number space is created, a
 * default global mutex is used.  The advantage to passing a mutex in, is
 * that the alloc_unrl() function can be called with the mutex already
 * held (it will not be released by alloc_unrl()).
 *
 * The allocation function alloc_unr{l}() never sleeps (but it may block on
 * the mutex of course).
 *
 * Freeing a unit number may require allocating memory, and can therefore
 * sleep so the free_unr() function does not come in a pre-locked variant.
 *
 * A userland test program is included.
 *
 * Memory usage is a very complex function of the exact allocation
 * pattern, but always very compact:
 *    * For the very typical case where a single unbroken run of unit
 *      numbers are allocated 44 bytes are used on i386.
 *    * For a unit number space of 1000 units and the random pattern
 *      in the usermode test program included, the worst case usage
 *	was 252 bytes on i386 for 500 allocated and 500 free units.
 *    * For a unit number space of 10000 units and the random pattern
 *      in the usermode test program included, the worst case usage
 *	was 798 bytes on i386 for 5000 allocated and 5000 free units.
 *    * The worst case is where every other unit number is allocated and
 *	the rest are free.  In that case 44 + N/4 bytes are used where
 *	N is the number of the highest unit allocated.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/_unrhdr.h>
#include <bitstring.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include "u_subr_unit.h"

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>
#endif


#ifdef __CHERI_PURE_CAPABILITY__
void* global_sealing_bitmap = NULL;
int global_sealing_bitmap_size = 0;
bool global_cheri_otypes_initialized = false;
struct cheri_revoke_info *cri;
struct unrhdr cheri_otypes;
struct unrhdr* cheri_otypes_ptr = NULL;
inline struct unrhdr*
get_global_cheri_otypes(void)
{
	if (!global_cheri_otypes_initialized) {
		cheri_otypes_ptr = &cheri_otypes;
		init_unrhdr(cheri_otypes_ptr, CHERI_OTYPE_USER_MIN,
		    CHERI_OTYPE_USER_MAX, NULL);
		global_cheri_otypes_initialized = true;
	}
	return cheri_otypes_ptr;
}
#endif

inline void*  get_global_sealing_bitmap(int* size_out)
{
#ifdef __CHERI_PURE_CAPABILITY__
	if (global_sealing_bitmap == NULL) {
		if (cheri_revoke_get_shadow(CHERI_CC_SEALING_BITMAP, NULL,
			&global_sealing_bitmap) != 0) {
			if (size_out)
				*size_out = 0;
			return NULL;
		}
		global_sealing_bitmap_size = __builtin_cheri_length_get(global_sealing_bitmap);
	}
#endif
	if (size_out)
		*size_out = global_sealing_bitmap_size;
	return global_sealing_bitmap;
}

#define KASSERT(cond, arg) \
	do { \
		if (!(cond)) { \
			printf arg; \
			abort(); \
		} \
	} while (0)

static int no_alloc;
#define Malloc(foo) _Malloc(foo, __LINE__)
static void *
_Malloc(size_t foo, int line)
{

	KASSERT(no_alloc == 0, ("malloc in wrong place() line %d", line));
	return (mrs_calloc_unr(foo, 1));
}
#define Free(foo) free(foo)

struct unrhdr;

#define	UNR_NO_MTX	((void *)(uintptr_t)-1)

struct mtx {
	atomic_flag state;
};

static struct mtx unitmtx = { ATOMIC_FLAG_INIT };

static void
mtx_lock(struct mtx *mp)
{
    while (atomic_flag_test_and_set(&mp->state)) {
        // spin until the flag is cleared
    }
}

static void
mtx_unlock(struct mtx *mp)
{
	atomic_flag_clear(&mp->state);
}

#define MA_OWNED	9

static void
mtx_assert(struct mtx *mp, int flag)
{
	if (flag == MA_OWNED) {
		KASSERT(atomic_flag_test_and_set(&mp->state), ("mtx_assert(MA_OWNED) not true"));
	}
}

#define CTASSERT(foo)
#define WITNESS_WARN(flags, lock, fmt, ...)	(void)0

/*
 * This is our basic building block.
 *
 * It can be used in three different ways depending on the value of the ptr
 * element:
 *     If ptr is NULL, it represents a run of free items.
 *     If ptr points to the unrhdr it represents a run of allocated items.
 *     Otherwise it points to a bitstring of allocated items.
 *
 * For runs the len field is the length of the run.
 * For bitmaps the len field represents the number of allocated items.
 *
 * The bitmap is the same size as struct unr to optimize memory management.
 *
 * Two special ranges are not covered by unrs:
 * - at the start of the allocator space, all elements in [low, low + first)
 *   are allocated;
 * - at the end of the allocator space, all elements in [high - last, high]
 *   are free.
 */
struct unr {
	TAILQ_ENTRY(unr)	list;
	u_int			len;
	void			*ptr;
};

struct unrb {
	bitstr_t		map[sizeof(struct unr) / sizeof(bitstr_t)];
};

CTASSERT((sizeof(struct unr) % sizeof(bitstr_t)) == 0);

/* Number of bits we can store in the bitmap */
#define NBITS (NBBY * sizeof(((struct unrb *)NULL)->map))

static inline bool
is_bitmap(struct unrhdr *uh, struct unr *up)
{
	return (up->ptr != uh && up->ptr != NULL);
}

/* Is the unrb empty in at least the first len bits? */
static inline bool
ub_empty(struct unrb *ub, int len) {
	int first_set;

	bit_ffs(ub->map, len, &first_set);
	return (first_set == -1);
}

/* Is the unrb full?  That is, is the number of set elements equal to len? */
static inline bool
ub_full(struct unrb *ub, int len)
{
	int first_clear;

	bit_ffc(ub->map, len, &first_clear);
	return (first_clear == -1);
}

/*
 * start: ipos = -1, upos = NULL;
 * end:   ipos = -1, upos = uh
 */
struct unrhdr_iter {
	struct unrhdr *uh;
	int ipos;
	int upos_first_item;
	void *upos;
};

void *
create_iter_unr(struct unrhdr *uh)
{
	struct unrhdr_iter *iter;

	iter = Malloc(sizeof(*iter));
	iter->ipos = -1;
	iter->uh = uh;
	iter->upos = NULL;
	iter->upos_first_item = -1;
	return (iter);
}

static void
next_iter_unrl(struct unrhdr *uh, struct unrhdr_iter *iter)
{
	struct unr *up;
	struct unrb *ub;
	u_int y;
	int c;

	if (iter->ipos == -1) {
		if (iter->upos == uh)
			return;
		y = uh->low - 1;
		if (uh->first == 0) {
			up = TAILQ_FIRST(&uh->head);
			if (up == NULL) {
				iter->upos = uh;
				return;
			}
			iter->upos = up;
			if (up->ptr == NULL)
				iter->upos = NULL;
			else
				iter->upos_first_item = uh->low;
		}
	} else {
		y = iter->ipos;
	}

	up = iter->upos;

	/* Special case for the compacted [low, first) run. */
	if (up == NULL) {
		if (y + 1 < uh->low + uh->first) {
			iter->ipos = y + 1;
			return;
		}
		up = iter->upos = TAILQ_FIRST(&uh->head);
		iter->upos_first_item = uh->low + uh->first;
	}

	for (;;) {
		if (y + 1 < iter->upos_first_item + up->len) {
			if (up->ptr == uh) {
				iter->ipos = y + 1;
				return;
			} else if (is_bitmap(uh, up)) {
				ub = up->ptr;
				bit_ffs_at(&ub->map[0],
				    y + 1 - iter->upos_first_item,
				    up->len, &c);
				if (c != -1) {
					iter->ipos = iter->upos_first_item + c;
					return;
				}
			}
		}
		iter->upos_first_item += up->len;
		y = iter->upos_first_item - 1;
		up = iter->upos = TAILQ_NEXT((struct unr *)iter->upos, list);
		if (iter->upos == NULL) {
			iter->ipos = -1;
			iter->upos = uh;
			return;
		}
	}
}

/*
 * returns -1 on end, otherwise the next element
 */
int
next_iter_unr(void *handle)
{
	struct unrhdr *uh;
	struct unrhdr_iter *iter;

	iter = handle;
	uh = iter->uh;
	if (uh->mtx != NULL)
		mtx_lock(uh->mtx);
	next_iter_unrl(uh, iter);
	if (uh->mtx != NULL)
		mtx_unlock(uh->mtx);
	return (iter->ipos);
}

void
free_iter_unr(void *handle)
{
	Free(handle);
}

#if defined(DIAGNOSTIC) || !defined(_KERNEL)
#ifndef __diagused
#define	__diagused
#endif

/*
 * Consistency check function.
 *
 * Checks the internal consistency as well as we can.
 *
 * Called at all boundaries of this API.
 */
inline void check_unrhdr(struct unrhdr *uh __unused, int line __unused)
{
	return;

	struct unr *up;
	struct unrb *ub;
	int w;
	u_int y __diagused, z __diagused;

	y = uh->first;
	z = 0;
	
	//int available = 0;
	//int claimed = 0; 
	//int bitmap = 0;
	//int counter = 0;

	TAILQ_FOREACH(up, &uh->head, list) {
		z++;
		if (is_bitmap(uh, up)) {
			ub = up->ptr;
			KASSERT (up->len <= NBITS,
			    ("UNR inconsistency: len %u max %zd (line %d)\n",
			    up->len, NBITS, line));
			z++;
			w = 0;
			bit_count(ub->map, 0, up->len, &w);
			y += w;
		} else if (up->ptr != NULL){
			y += up->len;
		}else{
		}
	}
	if(z != uh->alloc || y != uh->busy){
		printf_uh(uh);
	}
	KASSERT (z == uh->alloc,
	    ("UNR inconsistency: chunks %u found %u (line %d)\n",
	    uh->alloc, z, line));
	KASSERT (y == uh->busy,
	    ("UNR inconsistency: items %u found %u (line %d)\n",
	    uh->busy, y, line));
}

#else

static __inline void
check_unrhdr(struct unrhdr *uh __unused, int line __unused)
{

}

#endif

/*
 * Userland memory management.  Just use calloc and keep track of how
 * many elements we have allocated for check_unrhdr().
 */

static __inline void *
new_unr(struct unrhdr *uh, void **p1, void **p2)
{
	void *p;

	uh->alloc++;
	KASSERT(*p1 != NULL || *p2 != NULL, ("Out of cached memory"));
	if (*p1 != NULL) {
		p = *p1;
		*p1 = NULL;
		return (p);
	} else {
		p = *p2;
		*p2 = NULL;
		return (p);
	}
}

static __inline void
delete_unr(struct unrhdr *uh, void *ptr)
{
	struct unr *up;

	uh->alloc--;
	up = ptr;
	TAILQ_INSERT_TAIL(&uh->ppfree, up, list);
}

void
clean_unrhdrl(struct unrhdr *uh)
{
	struct unr *up;

	if (uh->mtx != NULL)
		mtx_assert(uh->mtx, MA_OWNED);
	while ((up = TAILQ_FIRST(&uh->ppfree)) != NULL) {
		TAILQ_REMOVE(&uh->ppfree, up, list);
		if (uh->mtx != NULL)
			mtx_unlock(uh->mtx);
		Free(up);
		if (uh->mtx != NULL)
			mtx_lock(uh->mtx);
	}

}
void
clean_unrhdr(struct unrhdr *uh)
{

	if (uh->mtx != NULL)
		mtx_lock(uh->mtx);
	clean_unrhdrl(uh);
	if (uh->mtx != NULL)
		mtx_unlock(uh->mtx);
}

void
init_unrhdr(struct unrhdr *uh, int low, int high, struct mtx *mutex)
{

	KASSERT(low >= 0 && low <= high,
	    ("UNR: use error: new_unrhdr(%d, %d)", low, high));
	if (mutex == UNR_NO_MTX)
		uh->mtx = NULL;
	else if (mutex != NULL)
		uh->mtx = mutex;
	else
		uh->mtx = &unitmtx;
	
	TAILQ_INIT(&uh->head);
	TAILQ_INIT(&uh->ppfree);
	uh->low = low;
	uh->high = high;
	uh->first = 0;
	uh->last = 1 + (high - low);
	uh->busy = 0;
	uh->alloc = 0;
	check_unrhdr(uh, __LINE__);
}

/*
 * Allocate a new unrheader set.
 *
 * Highest and lowest valid values given as parameters.
 */

struct unrhdr *
new_unrhdr(int low, int high, struct mtx *mutex)
{
	struct unrhdr *uh;

	uh = Malloc(sizeof *uh);
	init_unrhdr(uh, low, high, mutex);
	return (uh);
}

void
delete_unrhdr(struct unrhdr *uh)
{

	check_unrhdr(uh, __LINE__);
	KASSERT(uh->busy == 0, ("unrhdr has %u allocations", uh->busy));
	KASSERT(uh->alloc == 0, ("UNR memory leak in delete_unrhdr"));
	KASSERT(TAILQ_FIRST(&uh->ppfree) == NULL,
	    ("unrhdr has postponed item for free"));
	Free(uh);
}

void
clear_unrhdr(struct unrhdr *uh)
{
	struct unr *up, *uq;

	KASSERT(TAILQ_EMPTY(&uh->ppfree),
	    ("unrhdr has postponed item for free"));
	TAILQ_FOREACH_SAFE(up, &uh->head, list, uq) {
		if (up->ptr != uh) {
			Free(up->ptr);
		}
		Free(up);
	}
	uh->busy = 0;
	uh->alloc = 0;
	init_unrhdr(uh, uh->low, uh->high, uh->mtx);

	check_unrhdr(uh, __LINE__);
}

void copy_unrhdr(struct unrhdr *old_uh, struct unrhdr *new_uh){
	struct unr* up;
	check_unrhdr(old_uh, 0);
	new_uh->head = old_uh->head;
	new_uh->low = old_uh->low;
	new_uh->high = old_uh->high;
	new_uh->busy = old_uh->busy;
	new_uh->alloc = old_uh->alloc;
	new_uh->first = old_uh->first;
	new_uh->last = old_uh->last;
	TAILQ_FOREACH(up, &new_uh->head, list) {
		if(up->ptr==old_uh){
			up->ptr=new_uh;
		}
	}
	check_unrhdr(new_uh, 0);
	return;
}

/*
 * Look for sequence of items which can be combined into a bitmap, if
 * multiple are present, take the one which saves most memory.
 *
 * Return (1) if a sequence was found to indicate that another call
 * might be able to do more.  Return (0) if we found no suitable sequence.
 *
 * NB: called from alloc_unr(), no new memory allocation allowed.
 */

/*
 * See if a given unr should be collapsed with a neighbor.
 *
 * NB: called from alloc_unr(), no new memory allocation allowed.
 */

static void
collapse_unr(struct unrhdr *uh, struct unr *up)
{
	struct unr *upp;
	struct unrb *ub;
	/* If bitmap is all set or clear, change it to runlength */
	if (is_bitmap(uh, up)) {
		ub = up->ptr;
		if (ub_full(ub, up->len)) {
			delete_unr(uh, up->ptr);
			up->ptr = uh;
		} else if (ub_empty(ub, up->len)) {
			delete_unr(uh, up->ptr);
			up->ptr = NULL;
		}
	}
	/* If nothing left in runlength, delete it */
	if (up->len == 0) {
		upp = TAILQ_PREV(up, unrhd, list);
		if (upp == NULL)
			upp = TAILQ_NEXT(up, list);
		TAILQ_REMOVE(&uh->head, up, list);
		delete_unr(uh, up);
		up = upp;
	}

	/* If we have "hot-spot" still, merge with neighbor if possible */
	if (up != NULL) {
		upp = TAILQ_PREV(up, unrhd, list);
		if (upp != NULL && up->ptr == upp->ptr) {
			up->len += upp->len;
			TAILQ_REMOVE(&uh->head, upp, list);
			delete_unr(uh, upp);
			}
		upp = TAILQ_NEXT(up, list);
		if (upp != NULL && up->ptr == upp->ptr) {
			up->len += upp->len;
			TAILQ_REMOVE(&uh->head, upp, list);
			delete_unr(uh, upp);
		}
	}

	/* Merge into ->first if possible */
	upp = TAILQ_FIRST(&uh->head);
	if (upp != NULL && upp->ptr == uh) {
		uh->first += upp->len;
		TAILQ_REMOVE(&uh->head, upp, list);
		delete_unr(uh, upp);
		if (up == upp)
			up = NULL;
	}

	/* Merge into ->last if possible */
	upp = TAILQ_LAST(&uh->head, unrhd);
	if (upp != NULL && upp->ptr == NULL) {
		uh->last += upp->len;
		TAILQ_REMOVE(&uh->head, upp, list);
		delete_unr(uh, upp);
		if (up == upp)
			up = NULL;
	}

	/* Try to make bitmaps */
	//while (optimize_unr(uh))
	//	continue;
}

/*
 * Allocate a free unr.
 */
int
alloc_unrl(struct unrhdr *uh)
{
	struct unr *up;
	struct unrb *ub;
	u_int x;
	int y;

	if (uh->mtx != NULL)
		mtx_assert(uh->mtx, MA_OWNED);
	check_unrhdr(uh, __LINE__);
	x = uh->low + uh->first;

	up = TAILQ_FIRST(&uh->head);

	/*
	 * If we have an ideal split, just adjust the first+last
	 */
	if (up == NULL && uh->last > 0) {
		uh->first++;
		uh->last--;
		uh->busy++;
		if(x<0){
			printf("error1 %d\n", x);
		}
		return (x);
	}

	/*
	 * We can always allocate from the first list element, so if we have
	 * nothing on the list, we must have run out of unit numbers.
	 */
	if (up == NULL)
		return (-1);

	KASSERT(up->ptr != uh, ("UNR first element is allocated"));

	if (up->ptr == NULL) {	/* free run */
		uh->first++;
		up->len--;
	} else {		/* bitmap */
		ub = up->ptr;
		bit_ffc(ub->map, up->len, &y);
		KASSERT(y != -1, ("UNR corruption: No clear bit in bitmap."));
		bit_set(ub->map, y);
		x += y;
	}
	uh->busy++;
	collapse_unr(uh, up);
	if(x<0){
		printf("error2 %d\n", x);
	}
	return (x);
}

int
alloc_unr(struct unrhdr *uh)
{
	int i;

	if (uh->mtx != NULL)
		mtx_lock(uh->mtx);
	i = alloc_unrl(uh);
	clean_unrhdrl(uh);
	if (uh->mtx != NULL)
		mtx_unlock(uh->mtx);
	return (i);
}

static int
alloc_unr_specificl(struct unrhdr *uh, u_int item, void **p1, void **p2)
{
	struct unr *up, *upn;
	struct unrb *ub;
	u_int i, last, tl;

	if (uh->mtx != NULL)
		mtx_assert(uh->mtx, MA_OWNED);

	if (item < uh->low + uh->first || item > uh->high)
		return (-1);

	up = TAILQ_FIRST(&uh->head);
	/* Ideal split. */
	if (up == NULL && item - uh->low == uh->first) {
		uh->first++;
		uh->last--;
		uh->busy++;
		check_unrhdr(uh, __LINE__);
		return (item);
	}

	i = item - uh->low - uh->first;

	if (up == NULL) {
		up = new_unr(uh, p1, p2);
		up->ptr = NULL;
		up->len = i;
		TAILQ_INSERT_TAIL(&uh->head, up, list);
		up = new_unr(uh, p1, p2);
		up->ptr = uh;
		up->len = 1;
		TAILQ_INSERT_TAIL(&uh->head, up, list);
		uh->last = uh->high - uh->low - i;
		uh->busy++;
		check_unrhdr(uh, __LINE__);
		return (item);
	} else {
		/* Find the item which contains the unit we want to allocate. */
		TAILQ_FOREACH(up, &uh->head, list) {
			if (up->len > i)
				break;
			i -= up->len;
		}
	}

	if (up == NULL) {
		if (i > 0) {
			up = new_unr(uh, p1, p2);
			up->ptr = NULL;
			up->len = i;
			TAILQ_INSERT_TAIL(&uh->head, up, list);
		}
		up = new_unr(uh, p1, p2);
		up->ptr = uh;
		up->len = 1;
		TAILQ_INSERT_TAIL(&uh->head, up, list);
		goto done;
	}

	if (is_bitmap(uh, up)) {
		ub = up->ptr;
		if (bit_test(ub->map, i) == 0) {
			bit_set(ub->map, i);
			goto done;
		} else
			return (-1);
	} else if (up->ptr == uh)
		return (-1);

	KASSERT(up->ptr == NULL,
	    ("alloc_unr_specificl: up->ptr != NULL (up=%p)", up));

	/* Split off the tail end, if any. */
	tl = up->len - (1 + i);
	if (tl > 0) {
		upn = new_unr(uh, p1, p2);
		upn->ptr = NULL;
		upn->len = tl;
		TAILQ_INSERT_AFTER(&uh->head, up, upn, list);
	}

	/* Split off head end, if any */
	if (i > 0) {
		upn = new_unr(uh, p1, p2);
		upn->len = i;
		upn->ptr = NULL;
		TAILQ_INSERT_BEFORE(up, upn, list);
	}
	up->len = 1;
	up->ptr = uh;

done:
	last = uh->high - uh->low - (item - uh->low);
	if (uh->last > last)
		uh->last = last;
	uh->busy++;
	collapse_unr(uh, up);
	check_unrhdr(uh, __LINE__);
	return (item);
}

int
alloc_unr_specific(struct unrhdr *uh, u_int item)
{
	void *p1, *p2;
	int i;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "alloc_unr_specific");

	p1 = Malloc(sizeof(struct unr));
	p2 = Malloc(sizeof(struct unr));

	if (uh->mtx != NULL)
		mtx_lock(uh->mtx);
	i = alloc_unr_specificl(uh, item, &p1, &p2);
	if (uh->mtx != NULL)
		mtx_unlock(uh->mtx);

	if (p1 != NULL)
		Free(p1);
	if (p2 != NULL)
		Free(p2);

	return (i);
}

/*
 * Free a unr.
 *
 * If we can save unrs by using a bitmap, do so.
 */
static void
free_unrl(struct unrhdr *uh, u_int item, void **p1, void **p2)
{
	struct unr *up, *upp, *upn;
	struct unrb *ub;
	u_int pl;

	KASSERT(item >= uh->low && item <= uh->high,
	    ("UNR: free_unr(%u) out of range [%u...%u]",
	     item, uh->low, uh->high));
	check_unrhdr(uh, __LINE__);
	item -= uh->low;
	upp = TAILQ_FIRST(&uh->head);
	/*
	 * Freeing in the ideal split case
	 */
	if (item + 1 == uh->first && upp == NULL) {
		uh->last++;
		uh->first--;
		uh->busy--;
		check_unrhdr(uh, __LINE__);
		return;
	}
	/*
 	 * Freeing in the ->first section.  Create a run starting at the
	 * freed item.  The code below will subdivide it.
	 */
	if (item < uh->first) {
		up = new_unr(uh, p1, p2);
		up->ptr = uh;
		up->len = uh->first - item;
		TAILQ_INSERT_HEAD(&uh->head, up, list);
		uh->first -= up->len;
	}

	item -= uh->first;

	/* Find the item which contains the unit we want to free */
	TAILQ_FOREACH(up, &uh->head, list) {
		if (up->len > item)
			break;
		item -= up->len;
	}

	/* Handle bitmap items */
	if (is_bitmap(uh, up)) {
		ub = up->ptr;

		KASSERT(bit_test(ub->map, item) != 0,
		    ("UNR: Freeing free item %d (bitmap)\n", item));
		bit_clear(ub->map, item);
		uh->busy--;
		collapse_unr(uh, up);
		return;
	}

	KASSERT(up->ptr == uh, ("UNR Freeing free item %d (run))\n", item));

	/* Just this one left, reap it */
	if (up->len == 1) {
		up->ptr = NULL;
		uh->busy--;
		collapse_unr(uh, up);
		return;
	}

	/* Check if we can shift the item into the previous 'free' run */
	upp = TAILQ_PREV(up, unrhd, list);
	if (item == 0 && upp != NULL && upp->ptr == NULL) {
		upp->len++;
		up->len--;
		uh->busy--;
		collapse_unr(uh, up);
		return;
	}

	/* Check if we can shift the item to the next 'free' run */
	upn = TAILQ_NEXT(up, list);
	if (item == up->len - 1 && upn != NULL && upn->ptr == NULL) {
		upn->len++;
		up->len--;
		uh->busy--;
		collapse_unr(uh, up);
		return;
	}

	/* Split off the tail end, if any. */
	pl = up->len - (1 + item);
	if (pl > 0) {
		upp = new_unr(uh, p1, p2);
		upp->ptr = uh;
		upp->len = pl;
		TAILQ_INSERT_AFTER(&uh->head, up, upp, list);
	}

	/* Split off head end, if any */
	if (item > 0) {
		upp = new_unr(uh, p1, p2);
		upp->len = item;
		upp->ptr = uh;
		TAILQ_INSERT_BEFORE(up, upp, list);
	}
	up->len = 1;
	up->ptr = NULL;
	uh->busy--;
	collapse_unr(uh, up);
}

void
free_unr(struct unrhdr *uh, u_int item)
{
	void *p1, *p2;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "free_unr");
	p1 = Malloc(sizeof(struct unr));
	p2 = Malloc(sizeof(struct unr));
	if (uh->mtx != NULL)
		mtx_lock(uh->mtx);
	free_unrl(uh, item, &p1, &p2);
	clean_unrhdrl(uh);
	if (uh->mtx != NULL)
		mtx_unlock(uh->mtx);
	if (p1 != NULL)
		Free(p1);
	if (p2 != NULL)
		Free(p2);
}

static inline u_int64_t get_sealing_word(u_int64_t* sealing_bitmap, int index){
	KASSERT(index%64==0, ("index not at start of word"));
	int word_offset = index/64;
	return sealing_bitmap[word_offset];
}

static inline char get_sealing_byte(u_int64_t sealing_bitmap_word, int index){
	KASSERT((size_t)index < sizeof(u_int64_t), ("sealing bitmap byte out of bounds"));
	return (char)((sealing_bitmap_word>>(index*8))&255);
}

static inline int get_sealing_bit(u_int64_t sealing_bitmap_word, int index){
	KASSERT((size_t)index < sizeof(u_int64_t)*8, ("sealing bitmap bit out of bounds"));
	return (int)((sealing_bitmap_word>>index)&1);
}

//create the bitmap by reusing the first two elememnts
//returns 1 if the last run in the window is fully removed
static int form_bitmap(struct unrhdr* uh, struct unr* prev_unr __unused, struct unr* new_unr __unused, struct lb_window* lookback_window){
	int ret = 0;

	//transform first run into a bitmap
	struct unr* firstrun = lookback_window->back_pointer;

	int bitmap_size = firstrun->len;
	struct unr* cur_run = TAILQ_NEXT(firstrun, list);
	KASSERT(cur_run!=NULL, ("window should contain more than one run"));
	lookback_window->alloc_count--;
	lookback_window->len-=firstrun->len;
	TAILQ_REMOVE(&uh->head, firstrun, list);

	int type = !(firstrun->ptr == NULL);
	struct unrb* new_bitmap = (struct unrb*)firstrun;
	if(type){
		bit_nset(new_bitmap->map, 0, bitmap_size-1);
	}else{
		bit_nclear(new_bitmap->map, 0, bitmap_size-1);
	}


	struct unr* second_run = cur_run; //keep track of second run, we will reuse this to point to the bitmap
	//iterate over the runs in the window to place their bits in the bitmap
	while(cur_run!=lookback_window->fowards_pointer){
		type = !(cur_run->ptr == NULL);
		if(type){
			bit_nset(new_bitmap->map, bitmap_size, bitmap_size+cur_run->len-1);
		}else{
			bit_nclear(new_bitmap->map, bitmap_size, bitmap_size+cur_run->len-1);
		}
		bitmap_size += cur_run->len;

		struct unr* u = cur_run;
		cur_run = TAILQ_NEXT(cur_run, list);
		KASSERT(cur_run!=NULL, ("window should contain more than two runs"));

		lookback_window->alloc_count--;
		lookback_window->len-=u->len;
		if(u!=second_run){
			TAILQ_REMOVE(&uh->head, u, list); //remove every run in the window except the first second and last
			delete_unr(uh, u);
		}
	}
	//this last run may not fit fully in the bitmap
	int leftover_size = sizeof(struct unrb)*8-bitmap_size;
	lookback_window->len-=leftover_size;
	KASSERT(leftover_size>0, ("There should still be some space for at least part of the last run, leftover size: %d", leftover_size));
	type = !(cur_run->ptr == NULL);
	if(type){
		bit_nset(new_bitmap->map, bitmap_size, bitmap_size+leftover_size-1);
	}else{
		bit_nclear(new_bitmap->map, bitmap_size, bitmap_size+leftover_size-1);
	}

	cur_run->len -= leftover_size;

	KASSERT(cur_run->len>=0, ("leftover run cannot have negative size"));
	if(cur_run->len==0){
		TAILQ_REMOVE(&uh->head, cur_run, list);//remove the last run if it fully falls in the window
		delete_unr(uh, cur_run);
		lookback_window->alloc_count--;
		ret = 1;
	}

	second_run->len = sizeof(struct unrb)*8;
	second_run->ptr = new_bitmap;
	return ret;
}

//update the lookback window. if it gets big enhough and there are enough runs in the window, try to form a bitmap.
static void try_form_bitmap(struct unrhdr* uh, struct unr* prev_unr, struct unr* new_unr, struct lb_window* lookback_window){
	if(lookback_window->back_pointer==NULL){
		KASSERT(lookback_window->fowards_pointer==NULL, ("back pointer and forward pointer shuold both be NULL or non-NULL"));
		lookback_window->fowards_pointer = new_unr;
		lookback_window->back_pointer = new_unr;
		return;
	}
	KASSERT(prev_unr!=NULL, ("There should be a prev unr element if the back and foward pointers are non-NULL"));

	if(prev_unr->len>=sizeof(struct unrb)*8){
		lookback_window->alloc_count = 0;
		lookback_window->len = 0;
		lookback_window->fowards_pointer = new_unr;
		lookback_window->back_pointer = new_unr;
		return;
	}
	//the prev unr is now fully in the window so lets add it.
	lookback_window->alloc_count++;
	lookback_window->len += prev_unr->len;
	if((size_t)lookback_window->len>=sizeof(struct unrb)*8){
		if(lookback_window->alloc_count>2){
			//there are more then 2 runs in the window, lets create a bitmap
			int res = form_bitmap(uh, prev_unr, new_unr, lookback_window);
			if(res){
				//the last run in the window was fully removed
				lookback_window->back_pointer = new_unr;
			}else{
				//the last run in the window was not fully removed
				lookback_window->back_pointer = prev_unr;
			}
		}else{
			//trow away the last run in the window until the size is less then 512
			while((size_t)lookback_window->len>=sizeof(struct unrb)*8){
				lookback_window->alloc_count--;
				lookback_window->len -= lookback_window->back_pointer->len;
				lookback_window->back_pointer = TAILQ_NEXT(lookback_window->back_pointer, list);
			}
			KASSERT(lookback_window->alloc_count!=0||
				lookback_window->back_pointer==new_unr, 
				("The foward and backpointer should match if the window contains no runs back pointer: %p, foward pointer: %p\n", 
					lookback_window->back_pointer, new_unr));
		}
	}
	lookback_window->fowards_pointer = new_unr;
	return;
}

//update the new_uh by increasing the size of the current unr or adding a new one. Returns the new_state
static int update_new_uh(struct unrhdr* new_uh, int new_state, int old_state, int size, struct lb_window* lookback_window){
	KASSERT(new_state==1||new_state==0, ("new state should be 0 or 1, new state: %d", new_state));
	KASSERT(old_state==1||old_state==0, ("old state should be 0 or 1, old state: %d", old_state));
	struct unr* u = TAILQ_LAST(&new_uh->head, unrhd);
	if(new_state==1){
		new_uh->busy += size;	
		if(old_state==new_state){
			if(u==NULL){
				//this is still the first run so add size to the first run
				new_uh->first += size;
			}else{
				//add size to the last unr object and make sure it is a run of claimed numbers
				KASSERT(u->ptr==new_uh, ("state of current unr should be claimed, unr ptr: %p", u->ptr));
				u->len += size;
			}
		}else{
			struct unr* new_u = (struct unr*)Malloc(sizeof(struct unr));
			//create new unr object of claimed numbers
			if(u==NULL){
				TAILQ_INSERT_HEAD(&new_uh->head, new_u, list);
			}else{
				TAILQ_INSERT_TAIL(&new_uh->head, new_u, list);
			}
			new_u->ptr = new_uh;
			new_u->len = size;
			
			new_uh->alloc++;
			try_form_bitmap(new_uh, u, new_u, lookback_window);
		}
	}else{
		if(old_state==new_state){
			//add size to the last unr object and make sure it is a run of available numbers
			KASSERT(u->ptr==NULL, ("state of current unr should be claimed, unr ptr: %p", u->ptr));
			u->len += size;
		}else{
			//create new run of available numbers
			struct unr* new_u = (struct unr*)Malloc(sizeof(struct unr));
			TAILQ_INSERT_TAIL(&new_uh->head, new_u, list);
			new_u->ptr = NULL;
			new_u->len = size;

			new_uh->alloc++;
			try_form_bitmap(new_uh, u, new_u, lookback_window);
		}
	}
	new_uh->last -= size;
	return new_state;
}

//go through a byte of the sealing bitmap and update the new_uh, return the new_state at the and
static int iter_sealing_byte(struct unrhdr * new_uh, char sealing_byte, int old_state, struct lb_window* lookback_window){
	if(~sealing_byte==0){
		//all bits are 1
		return update_new_uh(new_uh, 0, old_state, 8, lookback_window);
	}
	if(sealing_byte==0){
		//all bits are 0
		return update_new_uh(new_uh, 1, old_state, 8, lookback_window);
	}
	for(int i=0;i<8;i++){
		int new_state = !((sealing_byte>>i)&1);
		old_state = update_new_uh(new_uh, new_state, old_state, 1, lookback_window);
	}
	return old_state;
}

static int get_updated_state(struct unrhdr* uh, struct unr* current_unr, int index, int sealing_state){
	int old_uh_state;
	if(current_unr->ptr==NULL){
		old_uh_state = 0;
	}else if(current_unr->ptr==uh){
		old_uh_state = 1;
	}else{
		struct unrb * ub = current_unr->ptr;
		old_uh_state = bit_test(ub->map, index);
	}
	
	if(old_uh_state==0){
		KASSERT(sealing_state==0, ("invalid state reached, unit number not claimed, but it is sealed"));
		return 0;
	}
	return !sealing_state;
}

static int unr_index_out_of_bounds(struct unrhdr* uh, struct unr* current_unr, int index){
	if(current_unr->ptr==NULL || current_unr->ptr==uh){
		return (u_int)index >= current_unr->len;
	}
	return (size_t)index >= sizeof(struct unrb)*8;
}

static void stage_two_free_many_unrl(struct unrhdr* old_uh, struct unrhdr* new_uh, u_int64_t* sealing_bitmap, struct unr* current_unr, int bitmap_index, int uh_state_new, struct lb_window* lookback_window){
	//now lets update the rest of the unr that are not part of the first run
	//the idea is the same, but we need to keep track of the state of the number in the original uh by iterating over it at the same pace as the sealing bitmap
	KASSERT(current_unr!=NULL, ("There should be at least one unr object. I have no idea how you even got here."));
	int unr_index = 0;
	//take the current word in the sealing bitmap
	u_int64_t sealing_bitmap_word = get_sealing_word(sealing_bitmap, (bitmap_index / 64) * 64);

	/* Run-length batching: track consecutive same-state bits */
	int run_state = uh_state_new;
	int run_length = 0;

	while(current_unr!=NULL){
		int sealing_bit = get_sealing_bit(sealing_bitmap_word, bitmap_index%64);
		int updated_state = get_updated_state(old_uh, current_unr, unr_index, sealing_bit);

		/* Batch consecutive same-state bits */
		if (updated_state == run_state) {
			run_length++;
		} else {
			/* State changed - flush previous run */
			if (run_length > 0) {
				uh_state_new = update_new_uh(new_uh, run_state, uh_state_new, run_length, lookback_window);
			}
			/* Start new run */
			run_state = updated_state;
			run_length = 1;
		}

		unr_index++;
		if(unr_index_out_of_bounds(old_uh, current_unr, unr_index)){
			unr_index = 0;
			current_unr = TAILQ_NEXT(current_unr, list);
			if(current_unr==NULL){
				/* Flush final run before returning */
				if (run_length > 0) {
					uh_state_new = update_new_uh(new_uh, run_state, uh_state_new, run_length, lookback_window);
				}
				struct unr* last_unr = TAILQ_LAST(&new_uh->head, unrhd);
				if(last_unr != NULL && last_unr->ptr==NULL){
					//combine the last run and uh->last if the last run type is available
					new_uh->last += last_unr->len;
					TAILQ_REMOVE(&new_uh->head, last_unr, list);
					delete_unr(new_uh, last_unr);
				}
				return;
			}
		}

		bitmap_index++;
		if(bitmap_index%64==0){
			//update sealing word when crossing word boundary
			sealing_bitmap_word = get_sealing_word(sealing_bitmap, bitmap_index);
		}
	}
}



/* given a pointer to the sealed bitmap (1="needs to be released", 0="stays claimed") return the the current bitmap index*/
static int stage_one_free_many_unr(struct unrhdr* uh, struct unrhdr* new_uh, u_int64_t* sealing_bitmap, struct lb_window* lookback_window, int* final_state){

	//first set all numbers that are part of the first run in the original uh in the new one based on the sealingbitmap
	//the "state" of the numbers in the original uh is 1 while bitmap_index is less then uh->first so do this first as it is easier
	const int first_run_size = uh->first;

	unsigned int bitmap_index = uh->low;
	int uh_state = 1; //0=available, 1=claimed
	//iterate over the sealing bitmap
	while((int)(bitmap_index-uh->low)<first_run_size){
		if(bitmap_index%64){
			//bitmap index is not word alligned, lets fix that
			int word_alligned_bitmap_index = (bitmap_index / 64) * 64;
			u_int64_t sealing_bitmap_word = get_sealing_word(sealing_bitmap, word_alligned_bitmap_index);
			for(int i=bitmap_index%64;i<64;i++){
				int updated_state = !((sealing_bitmap_word>>i)&1);	
				uh_state = update_new_uh(new_uh, updated_state, uh_state, 1, lookback_window);
				bitmap_index++;
			}
			continue;
		}else if((int)(bitmap_index-uh->low+64) >= (first_run_size+1)){
			//part of this word no longer maps to the first run
			u_int64_t sealing_bitmap_word = get_sealing_word(sealing_bitmap, bitmap_index);
			int leftover_bits = first_run_size - (bitmap_index-uh->low);
			for(int i=0;i<leftover_bits;i++){
				int updated_state = ~(sealing_bitmap_word>>i)&1;	
				uh_state = update_new_uh(new_uh, updated_state, uh_state, 1, lookback_window);
				bitmap_index++;
			}
			break;
		}

		u_int64_t sealing_bitmap_word = get_sealing_word(sealing_bitmap, bitmap_index);
		if(~sealing_bitmap_word==0){
			//all bits are 1
			uh_state = update_new_uh(new_uh, 0, uh_state, 64, lookback_window);
			bitmap_index += 64;
			continue;
		}
		if(sealing_bitmap_word==0){
			//all bits are 0
			uh_state = update_new_uh(new_uh, 1, uh_state, 64, lookback_window);
			bitmap_index += 64;
			continue;
		}

		for(size_t i=0;i<sizeof(u_int64_t);i++){
			char sealing_byte = get_sealing_byte(sealing_bitmap_word, (int)i);
			uh_state = iter_sealing_byte(new_uh, sealing_byte, uh_state, lookback_window);
			bitmap_index += 8;
		}
	}
	KASSERT((int)(bitmap_index-uh->low) == first_run_size, ("relative bitmap index should match first run size at this point"));
	*final_state = uh_state;
	return bitmap_index;
}


void free_many_unr(struct unrhdr** old_uh_ptr, u_int64_t* sealing_bitmap, int should_free_old_uh){
	struct lb_window lookback_window = {0};
	struct unrhdr* new_uh = new_unrhdr((*old_uh_ptr)->low, (*old_uh_ptr)->high, NULL);

	int uh_state_new;

	//lets start by iterating thought the first run of the old unrhdr, this does not require a lock because this first run can only increase in length
	int bitmap_index = stage_one_free_many_unr(*old_uh_ptr, new_uh, sealing_bitmap, &lookback_window, &uh_state_new);

	//now we need to lock the unit number allocator before starting stage two
	if ((*old_uh_ptr)->mtx != NULL)
		mtx_lock((*old_uh_ptr)->mtx);
	
	KASSERT((*old_uh_ptr)->first >= bitmap_index-(*old_uh_ptr)->low, ("first run should not have become shorter, first run: %d, current relative index: %d", (*old_uh_ptr)->first, bitmap_index-(*old_uh_ptr)->low));

	//it is possible that another thread increased the size of the first run during stage one, so lets complete it now we have a lock
	u_int64_t sealing_bitmap_word = get_sealing_word(sealing_bitmap, (bitmap_index / 64) * 64);
	while((bitmap_index-(*old_uh_ptr)->low) != (*old_uh_ptr)->first){
		int bitoff = bitmap_index%64;
		int updated_state = !((sealing_bitmap_word>>bitoff)&1);	
		uh_state_new = update_new_uh(new_uh, updated_state, uh_state_new, 1, &lookback_window);
		bitmap_index++;
		if(bitmap_index%64==0){
			sealing_bitmap_word = get_sealing_word(sealing_bitmap, bitmap_index);
		}
	}
	KASSERT((*old_uh_ptr)->first == (bitmap_index-(*old_uh_ptr)->low), ("You should have reached the end of the first run now, first run: %d, current relative index: %d", (*old_uh_ptr)->first, (bitmap_index-(*old_uh_ptr)->low)));
	
	//if all claimed numbers are in the first run, skip the second stage
	struct unr* first_unr = TAILQ_FIRST(&(*old_uh_ptr)->head);
	if(first_unr!=NULL){
		//if there are any unr objects, iterate though them as well
		stage_two_free_many_unrl(*old_uh_ptr, new_uh, sealing_bitmap, first_unr, bitmap_index, uh_state_new, &lookback_window);
	}else{
		struct unr* last_unr = TAILQ_LAST(&new_uh->head, unrhd);
		//combine the last run and uh->last if the last run type = "available"
		if(last_unr != NULL && last_unr->ptr==NULL){
			new_uh->last += last_unr->len;
			TAILQ_REMOVE(&new_uh->head, last_unr, list);
			delete_unr(new_uh, last_unr);
		}
	}

	//clear the old unrhdr and replace it by the new one
	struct unrhdr* temp = *old_uh_ptr;
	*old_uh_ptr = new_uh;
	check_unrhdr(*old_uh_ptr, __LINE__);
	clean_unrhdrl(temp);
	clear_unrhdr(temp);

	if (temp->mtx != NULL)
		mtx_unlock(temp->mtx);
	//if the old unrhdr is heap allocated, free it
	if(should_free_old_uh){
		free(temp);
	}
	return;
}

void printf_uh(struct unrhdr* uh){
	printf("address: %p,", uh);
	printf("low: %d, ", uh->low);
	printf("high: %d, ", uh->high);
	printf("busy: %d, ", uh->busy);
	printf("alloc: %d, ", uh->alloc);
	printf("first: %d, ", uh->first);
	printf("last: %d\n", uh->last);
}




#ifdef _KERNEL
#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>
#endif
#endif

#if (defined(_KERNEL) && defined(DDB)) || !defined(_KERNEL)

#if !defined(_KERNEL)
#define db_printf printf
#endif



void print_diff_from_iters(struct unrhdr *uh1, struct unrhdr *uh2) {
	struct unrhdr_iter *it1 = create_iter_unr(uh1);
	struct unrhdr_iter *it2 = create_iter_unr(uh2);
    int num1 = next_iter_unr(it1);
    int num2 = next_iter_unr(it2);

    while (num1 != -1) {
        while (num2 != -1 && num2 < num1) {
            num2 = next_iter_unr(it2);
        }
        if (num2 == -1 || num1 < num2) {
            printf("%d\n", num1); // print elements only in iter1
            num1 = next_iter_unr(it1);
        } else if (num1 == num2) {
            // skip common
            num1 = next_iter_unr(it1);
            num2 = next_iter_unr(it2);
        }
    }
}

#endif

#if defined(_KERNEL) && defined(DDB)
DB_SHOW_COMMAND(unrhdr, unrhdr_print_unrhdr)
{
	if (!have_addr) {
		db_printf("show unrhdr addr\n");
		return;
	}

	print_unrhdr(DB_DATA_PTR(addr, struct unrhdr));
}

static void
print_unrhdr_iter(struct unrhdr_iter *iter)
{
	db_printf("iter %p unrhdr %p ipos %d upos %p ufi %d\n",
	    iter, iter->uh, iter->ipos, iter->upos, iter->upos_first_item);
}

DB_SHOW_COMMAND(unrhdr_iter, unrhdr_print_iter)
{
	if (!have_addr) {
		db_printf("show unrhdr_iter addr\n");
		return;
	}

	print_unrhdr_iter(DB_DATA_PTR(addr, struct unrhdr_iter));
}
#endif
