/*-
 * Copyright (c) 2019 Brett F. Gutstein
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
 */

#include <sys/param.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/cpuset.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <cheri/libcaprevoke.h>

#include <machine/vmparam.h>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc_np.h>
#include <pthread.h>
#include <pthread_np.h>
#include <spinlock.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/elf.h>
#include <sys/bitstring.h>

#include "libc_private.h"
#include "mrs_utrace.h"
#include "../../u_subr_unit.h"
#include "../../_unrhdr.h"
#include "../../bitmap_otype_allocator.h"


/* Uncomment to use flat bitmap allocator instead of unr allocator */
#define BITMAP_ALLOCATOR_ACTIVATE

#ifdef BITMAP_ALLOCATOR_ACTIVATE
/* Struct instance and static bitmap defined here; functions in bitmap_otype_allocator.c */
#endif /* BITMAP_ALLOCATOR_ACTIVATE */

/*
 * Knobs:
 *
 * OFFLOAD_QUARANTINE: Process full quarantines in a separate thread.
 * MRS_PINNED_CPUSET: Prefer CPU 2 for the application thread and CPU
 *   3 for the offload thread.  Both threads are, by default, willing
 *   to run on CPUs 0 and 1, but we expect that the environment has
 *   restricted the default CPU set to only 0 and 1 and left 2 and 3
 *   available for the program under test and its revoker thread.
 *
 *   If !OFFLOAD_QUARANTINE, this still prevents the application from
 *   using CPU 3.
 * DEBUG: Print debug statements.
 * PRINT_STATS: Print statistics on exit.
 * PRINT_CAPREVOKE: Print stats for each CHERI revocation.
 * PRINT_CAPREVOKE_MRS: Print details of MRS operation around revocations.
 * CLEAR_ON_ALLOC: Zero allocated regions as they are allocated (for
 *   non-calloc allocation functions).
 * CLEAR_ON_RETURN: Zero allocated regions as they come out of quarantine.
 * CLEAR_ON_FREE: Zero allocated regions as they are given to us.
 * REVOKE_ON_FREE: Perform revocation on free rather than during
 *   allocation routines.
 *
 * Values:
 *
 * QUARANTINE_NUMERATOR / QUARANTINE_DENOMINATOR: Limit the quarantine
 * size to QUARANTINE_NUMERATOR / QUARANTINE_DENOMINATOR times the size
 * of the heap (default 1/4).
 */
#ifdef QUARANTINE_RATIO
#error QUARANTINE_RATIO is obsolete, use QUARANTINE_NUMERATOR/QUARANTINE_DENOMINATOR
#endif
#ifndef QUARANTINE_DENOMINATOR
#define	QUARANTINE_DENOMINATOR	4
#endif
#ifndef QUARANTINE_NUMERATOR
#define	QUARANTINE_NUMERATOR	1
#endif

#define	MALLOCX_LG_ALIGN_BITS	6
#define	MALLOCX_LG_ALIGN_MASK	((1 << MALLOCX_LG_ALIGN_BITS) - 1)
/* Use MALLOCX_ALIGN_GET() if alignment may not be specified in flags. */
#define	MALLOCX_ALIGN_GET_SPECIFIED(flags)				\
    ((size_t)1 << (flags & MALLOCX_LG_ALIGN_MASK))
#define	MALLOCX_ALIGN_GET(flags)					\
    (MALLOCX_ALIGN_GET_SPECIFIED(flags) & (SIZE_T_MAX - 1))

#ifdef SNMALLOC_PRINT_STATS
extern void snmalloc_print_stats(void);
#endif
#ifdef SNMALLOC_FLUSH
extern void snmalloc_flush_message_queue(void);
#endif

#define	MALLOC_QUARANTINE_DISABLE_ENV	"_RUNTIME_REVOCATION_DISABLE"
#define	MALLOC_QUARANTINE_ENABLE_ENV	"_RUNTIME_REVOCATION_ENABLE"
#define	MALLOC_ABORT_DISABLE_ENV	"_RUNTIME_ABORT_DISABLE"
#define	MALLOC_ABORT_ENABLE_ENV		"_RUNTIME_ABORT_ENABLE"

#define	MALLOC_REVOKE_EVERY_FREE_DISABLE_ENV \
	"_RUNTIME_REVOCATION_EVERY_FREE_DISABLE"
#define	MALLOC_REVOKE_EVERY_FREE_ENABLE_ENV \
	"_RUNTIME_REVOCATION_EVERY_FREE_ENABLE"
#define	MALLOC_REVOKE_SYNC_ENV \
	"_RUNTIME_REVOCATION_SYNC_REVOKE"
#define	MALLOC_REVOKE_ASYNC_ENV \
	"_RUNTIME_REVOCATION_ASYNC_REVOKE"
#define	MALLOC_BOUND_CHERI_POINTERS \
	"_RUNTIME_BOUND_CHERI_POINTERS"
#define	MALLOC_NOBOUND_CHERI_POINTERS \
	"_RUNTIME_NOBOUND_CHERI_POINTERS"

#define	MALLOC_QUARANTINE_DENOMINATOR_ENV \
	"_RUNTIME_QUARANTINE_DENOMINATOR"
#define	MALLOC_QUARANTINE_NUMERATOR_ENV \
	"_RUNTIME_QUARANTINE_NUMERATOR"

/*
 * Different allocators give their strong symbols different names.  Hide
 * this implementation detail being the REAL() macro.
 */
#define _REAL_PREPEND(f, pre)	pre##f
#define	_REAL_EVAL(f, pre)	_REAL_PREPEND(f, pre)
#define	REAL(f)	_REAL_EVAL(f, MRS_REAL_PREFIX)

void *REAL(malloc)(size_t);
void REAL(free)(void *);
void *REAL(calloc)(size_t, size_t);
void *REAL(realloc)(void *, size_t);
int REAL(posix_memalign)(void **, size_t, size_t);
void *REAL(aligned_alloc)(size_t, size_t);

/* jemalloc non-standard API */
void *REAL(mallocx)(size_t, int);
void *REAL(rallocx)(void *, size_t, int);
void REAL(dallocx)(void *, int);
void REAL(sdallocx)(void *, size_t, int);

/*
 * XXX: no support for v3 API (allocm, rallocm, sallocm, dallocm, nallocm).
 * The are provided in FreeBSD for backwards compatibility and are not
 * declared in any public header so there should be no users.
 */

/* functions */
static void* cc_set_objectid(void* p);
static void *mrs_malloc(size_t);
static void mrs_free(void *);
static void *mrs_calloc(size_t, size_t);
static void *mrs_realloc(void *, size_t);
static int mrs_posix_memalign(void **, size_t, size_t);
static void *mrs_aligned_alloc(size_t, size_t);

void *mrs_mallocx(size_t, int);
void *mrs_rallocx(void *, size_t, int);
void mrs_dallocx(void *, int);
void mrs_sdallocx(void *, size_t, int);

void *
malloc(size_t size)
{
	return (mrs_malloc(size));
}

void
free(void *ptr)
{
	return (mrs_free(ptr));
}

void *
calloc(size_t number, size_t size)
{
	return (mrs_calloc(number, size));
}

void *
realloc(void *ptr, size_t size)
{
	return (mrs_realloc(ptr, size));
}

int
posix_memalign(void **ptr, size_t alignment, size_t size)
{
	return (mrs_posix_memalign(ptr, alignment, size));
}

void *
aligned_alloc(size_t alignment, size_t size)
{
	return (mrs_aligned_alloc(alignment, size));
}

void *
mallocx(size_t size, int flags)
{
	return (mrs_mallocx(size, flags));
}

void *
rallocx(void *ptr, size_t size, int flags)
{
	return (mrs_rallocx(ptr, size, flags));
}

void
dallocx(void *ptr, int flags)
{
	return (mrs_dallocx(ptr, flags));
}

void
sdallocx(void *ptr, size_t size, int flags)
{
	return (mrs_sdallocx(ptr, size, flags));
}

/*
 * Defined by CHERIfied mallocs for use with mrs - given a capability returned
 * by the malloc that may have had its bounds shrunk, rederive and return a
 * capability with bounds corresponding to the original allocation.
 *
 * If the passed-in capability is tagged/permissioned and corresponds to some
 * allocation, give back a pointer with that same base whose length corresponds
 * to the underlying allocation size; otherwise return NULL.
 *
 * (For correspondence, check that its base matches the base of an allocation.
 * In practice, check that the offset is zero, which is necessary for the base
 * to match the base of any allocation, and then it is fine to compare the
 * address of the passed-in thing (which is the base) to whatever is necessary.
 * Note that the length of the passed-in capability doesn't matter as long as
 * the allocator uses the underlying size for rederivation or revocation.)
 *
 * This function will give back a pointer with SW_VMEM permission, so mrs can
 * clear its memory and free it back after revocation.  With mrs we assume the
 * attacker can't access this function, and in the post-mrs world it is
 * unnecessary.
 *
 * NB: As long as an allocator's allocations are naturally aligned
 * according to their size, as is the case for most slab/bibop allocators, it
 * is possible to check this condition by verifying that the passed-in
 * base/address is contained in the heap and is aligned to the size of
 * allocations in that heap region (power of 2 size or otherwise).  It may be
 * necessary to do something slightly more complicated, like checking
 * offset from the end of a slab in snmalloc.  In traditional free list
 * allocators, allocation metadata can be used to verify that the passed-in
 * pointer is legit.
 *
 * (Writeup needs more detail about exactly what allocators
 * will give back and expect in terms of base offset etc.)
 *
 * In an allocator that is not using mrs, similar logic should be used to
 * validate and/or rederive pointers and take actions accordingly on the free
 * path and any other function that accepts application pointers.  A pointer
 * passed to free must correspond appropriately as described above.  If it
 * doesn't then no action can be taken or you can abort.
 *
 * malloc_usable_size() and any other function taking in pointers similarly
 * needs validation.
 *
 * NB it is possible to do revocation safely with mrs only using a version of
 * malloc_usable_size() modified to give the size of the underlying allocation -
 * but this was done so that clearing on free could be evaluated easily and
 * so that allocators wouldn't have to accept revoked caps.
 */
void *REAL(malloc_underlying_allocation)(void *);

/* globals */

/*
 * Alignment requirement for allocations so they can be painted in the
 * caprevoke bitmap.
 *
 * XXX VM_CAPREVOKE_GSZ_MEM_NOMAP from machine/vmparam.h
 */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = sizeof(void *);
static const size_t DESCRIPTOR_SLAB_ENTRIES = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;


static size_t page_size;

/* Flags are constant after initialization. */
static bool quarantining = true;
static bool revoke_every_free = false;
static bool revoke_async = false;
static bool bound_pointers = false;
static bool abort_on_validation_failure = true;
static bool mrs_initialized = false;
static int cheri_otypes_threshold = CHERI_OTYPE_USER_MAX - 2000;

#ifdef BITMAP_ALLOCATOR_ACTIVATE
static uint64_t static_bitmap[(CHERI_OTYPE_USER_MAX - CHERI_OTYPE_USER_MIN + 64) / 64];
static struct bitmap_otype_allocator bitmap_otypes = {
	.bitmap = (bitstr_t *)static_bitmap,
	.low = CHERI_OTYPE_USER_MIN,
	.high = CHERI_OTYPE_USER_MAX,
	.busy = 0,
	.num_bits = CHERI_OTYPE_USER_MAX - CHERI_OTYPE_USER_MIN + 1,
	.hint = 0,
	.lock = ATOMIC_FLAG_INIT,
};
static struct bitmap_otype_allocator *bitmap_otypes_ptr = &bitmap_otypes;
#endif

static int revoke_count = 0;
static int malloc_count = 0;

static bool is_revoking = false;
static uint64_t epoch_count = 0;

static unsigned int quarantine_denominator = QUARANTINE_DENOMINATOR;
static unsigned int quarantine_numerator = QUARANTINE_NUMERATOR;

static spinlock_t mrs_init_lock = _SPINLOCK_INITIALIZER;
#define	MRS_LOCK(x)	__extension__ ({	\
	if (__isthreaded)			\
		_SPINLOCK(x);			\
})
#define	MRS_UNLOCK(x)	__extension__ ({	\
	if (__isthreaded)			\
		_SPINUNLOCK(x);			\
})

/*
 * Optionally apply strict bounds to pointers returned by malloc() and friends.
 * This is technically UB since it means that the pointer passed to free() is
 * not what we got from the allocator.  However, it may be useful for
 * demonstrating CHERI's spatial safety guarantees in demos and so on.
 *
 * The default behaviour lets the allocator provide pointers with bounds
 * covering the usable size of the allocation, beyond the requested size, which
 * is friendlier to realloc() loops.  With revocation enabled, strict bounds
 * would force a new allocation for each realloc() call, which can hurt quite a
 * bit.
 */
static void *
mrs_bound_pointer(void *p, size_t size)
{
	if (p != NULL && bound_pointers && size > 0)
		p = cheri_setbounds(p, size);
	return (p);
}

struct mrs_descriptor_slab_entry {
	void *ptr;
	size_t size;
};

struct mrs_descriptor_slab {
	int num_descriptors;
	struct mrs_descriptor_slab *next;
	struct mrs_descriptor_slab_entry slab[DESCRIPTOR_SLAB_ENTRIES];
};

struct mrs_quarantine {
	size_t size;
	size_t max_size;
	bool revoking;
	cheri_revoke_epoch_t epoch;	/* valid when revoking */
	struct mrs_descriptor_slab *list;
	TAILQ_ENTRY(mrs_quarantine) next;
};

/* XXX ABA and other issues ... should switch to atomics library */
static struct mrs_descriptor_slab * _Atomic free_descriptor_slabs;

/*
 * amount of memory that the allocator views as allocated (includes
 * quarantine)
 */
/*
 * Quarantine arenas for application threads.  At any given time, one is in
 * active use, and the others are being cleaned.
 */
#define	APP_QUARANTINE_ARENAS	2
_Static_assert(APP_QUARANTINE_ARENAS >= 2,
    "APP_QUARANTINE_ARENAS must be at least 2");

/* Arenas with revocation pending. */
static TAILQ_HEAD(, mrs_quarantine) app_quarantine_revoke_list =
    TAILQ_HEAD_INITIALIZER(app_quarantine_revoke_list);

static void quarantine_revoke();

#ifdef OFFLOAD_QUARANTINE
/* quarantine for the offload thread */
static struct mrs_quarantine offload_quarantine;
#endif /* OFFLOAD_QUARANTINE */

static inline __attribute__((always_inline)) void
mrs_puts(const char *p)
{
	size_t n = strlen(p);
	write(2, p, n);
}

/* locks */

#define mrs_lock(mtx) do {						\
	if (pthread_mutex_lock((mtx)) != 0) {				\
		mrs_puts("pthread error\n");				\
		exit(7);						\
	}								\
} while (0)

#define mrs_unlock(mtx) do {						\
	if (pthread_mutex_unlock((mtx)) != 0) {				\
		mrs_puts("pthread error\n");				\
		exit(7);						\
	}								\
} while (0)

/* returns true if lock acquired, false if already held */ 
#define mrs_trylock(mtx) ({ \
    int ret = pthread_mutex_trylock((mtx)); \
    if (ret != 0 && ret != EBUSY) { \
        mrs_puts("pthread error\n"); \
        exit(7); \
    } \
    (ret == 0); \
})

/*
 * Hack to initialize mutexes without calling malloc.  Without this, locking
 * operations in allocation functions would cause an infinite loop.  The buf
 * size should be at least sizeof(struct pthread_mutex) from thr_private.h
 */
#define create_lock(name)						\
	pthread_mutex_t name;						\
	char name ## _buf[256] __attribute__((aligned(16)));		\
									\
	void *								\
	name ## _storage(size_t num __unused, size_t size __unused)	\
	{								\
		return (name ## _buf);					\
	}

int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex,
    void *(calloc_cb)(size_t, size_t));
#pragma weak _pthread_mutex_init_calloc_cb

int
_pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex,
    void *(calloc_cb)(size_t, size_t))
{
	return (((int (*)(pthread_mutex_t *, void *(*)(size_t, size_t)))
	    __libc_interposing[INTERPOS__pthread_mutex_init_calloc_cb])(mutex,
	    calloc_cb));
}

#define initialize_lock(name)					\
	_pthread_mutex_init_calloc_cb(&name, name ## _storage)

create_lock(app_quarantine_lock);
create_lock(mrs_revoke_lock);

/* quarantine offload support */
#ifdef OFFLOAD_QUARANTINE
static void *mrs_offload_thread(void *);
create_lock(offload_quarantine_lock);
/*
 * No hack needed for these because condition variables are not used
 * in allocation routines.
 */
pthread_cond_t offload_quarantine_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t offload_quarantine_ready = PTHREAD_COND_INITIALIZER;
#endif /* OFFLOAD_QUARANTINE */

create_lock(printf_lock);
static void
mrs_printf(char *fmt, ...)
{
	char buf[1024];
	int n = 0, m;

	va_list va;
	va_start(va, fmt);

	m = snprintf(buf, sizeof(buf), "mrs[%d]: ", getpid());
	if (m < 0)
	{
		abort();
	}
	n += m;
	n = (n > sizeof(buf)) ? sizeof(buf) : n;

	m = vsnprintf(buf+n, sizeof(buf)-n, fmt, va);
	if (m < 0)
	{
		abort();
	}
	n += m;
	n = (n > sizeof(buf)) ? sizeof(buf) : n;

	mrs_lock(&printf_lock);
	write(2, buf, n);
	mrs_unlock(&printf_lock);
}

/* debugging */

#ifdef DEBUG
#define mrs_debug_printf(fmt, ...) mrs_printf(fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define mrs_debug_printf(fmt, ...)
#endif /* !DEBUG */

#define	MRS_UTRACE_ENV	"_MRS_UTRACE"

static bool mrs_utrace;

static void
mrs_utrace_log(int event, void *p, size_t s, size_t n, void *r)
{
	struct utrace_mrs ut;
	static const char mrs_utrace_sig[MRS_UTRACE_SIG_SZ] = MRS_UTRACE_SIG;

	memcpy(ut.sig, mrs_utrace_sig, sizeof(ut.sig));
	ut.event = event;
	ut.s = s;
	ut.p = __builtin_cheri_tag_clear(p);
	ut.r = __builtin_cheri_tag_clear(r);
	ut.n = n;
	utrace(&ut, sizeof(ut));
}

#define	MRS_UTRACE(...) do {					\
	if (mrs_utrace)						\
		mrs_utrace_log(__VA_ARGS__);			\
} while (0)

/* utilities */

static struct mrs_descriptor_slab *
alloc_descriptor_slab(void)
{
	if (free_descriptor_slabs == NULL) {
		mrs_debug_printf("alloc_descriptor_slab: mapping new memory\n");
		void *ret = mmap(NULL, sizeof(struct mrs_descriptor_slab),
		    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
		return ((ret == MAP_FAILED) ? NULL : ret);
	} else {
		mrs_debug_printf("alloc_descriptor_slab: reusing memory\n");
		struct mrs_descriptor_slab *ret = free_descriptor_slabs;

		while (!atomic_compare_exchange_weak(&free_descriptor_slabs,
		    &ret, ret->next))
			;

		ret->num_descriptors = 0;
		return (ret);
	}
}

/*
 * We assume that the consumer of this shim can issue arbitrary malicious
 * malloc/free calls.  To track the total allocated size effectively, we
 * accumulate the length of capabilities as they are returned by mrs_malloc.
 * For the quarantine size, tracking is different in the offload and
 * non-offload cases.  In the non-offload case, capabilities passed in to
 * mrs_free are validated and replaced with a rederived capability to the
 * entire allocation (obtained by calling the underlying allocator's
 * malloc_underlying_allocation() function) before being added to quarantine,
 * so we accumulate the length of capabilities in quarantine post-validation.
 * The result is that for each allocation, the same number is added to the
 * allocated size total and the quarantine size total.  When the quarantine is
 * flushed, the allocated size is reduced by the quarantine size and the
 * quarantine size is reset to zero.
 *
 * In the offload case, the application thread fills a quarantine with
 * unvalidated capabilities passed in to mrs_free() (which may be untagged,
 * duplicates, have shrunk bounds, etc.).  The lengths of these capabilities are
 * accumulated into the quarantine size, which is an approximation and only
 * used to trigger offload processing.  In the offload thread, a separate
 * accumulation is performed using only validated capabilities, and that is used
 * to reduce the allocated size after flushing.
 *
 * Sometimes malloc implementations are recursive in which case we leak some
 * space.  This was observed in snmalloc for allocations of size 0x20.
 */

static inline void
clear_region(void *mem, size_t len)
{
	static const size_t ZERO_THRESHOLD = 64;

	/*
	 * For small regions that are qword-multiple-sized, use writes to avoid
	 * memset call.  Alignment should be good in normal cases.
	 */
	if ((len <= ZERO_THRESHOLD) && (len % sizeof(uint64_t) == 0)) {
		for (size_t i = 0; i < (len / sizeof(uint64_t)); i++) {
			/*
			 * volatile needed to avoid memset call by
			 * compiler "optimization"
			 */
			((volatile uint64_t *)mem)[i] = 0;
		}
	} else {
		memset(mem, 0, len);
	}
}

/*
 * Given a pointer freed by the application, validate it by (1) checking that
 * the pointer has an underlying allocation (was actually allocated by the
 * allocator) and (2) using the bitmap painting function to make sure this
 * pointer is valid and hasn't already been freed or revoked.
 *
 * Returns a capability to the underlying allocation if validation was
 * successful, NULL otherwise.
 *
 * Supports ablation study knobs, returning NULL in case of a short circuit.
 */
static inline void *
validate_freed_pointer(void *ptr)
{

	/*
	 * Untagged check before malloc_underlying_allocation()
	 * catches NULL and other invalid caps that may cause a rude
	 * implementation of malloc_underlying_allocation() to crash.
	 */
	if (!cheri_gettag(ptr)) {
		mrs_debug_printf("validate_freed_pointer: untagged capability addr %p\n",
		    ptr);
		return (NULL);
	}

	void *underlying_allocation = REAL(malloc_underlying_allocation)(ptr);
	if (underlying_allocation == NULL) {
		mrs_debug_printf("validate_freed_pointer: not allocated by underlying allocator\n");
		return (NULL);
	}
	/*mrs_debug_printf("freed underlying allocation %#p\n", underlying_allocation);*/

	int otype = cheri_gettype(ptr);
	if(otype==-1){
		return (underlying_allocation);
	}
	int byte_offset = otype/8;
	int bit_offset = otype%8;
	char sealing_byte = ((char*)global_sealing_bitmap)[byte_offset];

	//verify that the memory is not already sealed
	if((sealing_byte>>bit_offset)&1){
		mrs_debug_printf("validate_freed_pointer: memory already freed\n");
		exit(-1);
	}
	//set sealing bitmap value
	((char*)global_sealing_bitmap)[byte_offset] = sealing_byte | (1<<bit_offset);
	asm("fence\n\t");

	return (underlying_allocation);
}

/*
 * Kick off an asynchronous revocation pass for the current application
 * quarantine arena, and/or check to see whether a previously scheduled pass has
 * completed.
 *
 * This function assumes that the application quarantine lock is held and will
 * drop it before returning.
 */
static int count_bitmap(u_int64_t* sealing_bitmap, int size){
	int count = 0;
	for(int i=0;i<size/sizeof(u_int64_t);i++){
		u_int64_t word = sealing_bitmap[i];
		for(int bit_offset = 0;bit_offset<sizeof(u_int64_t)*8;bit_offset++){
			if((word>>bit_offset)&1){
				count++;
			}
		}
	}
	return count;
}

/*
 * Persistent sealing bitmap copy - allocated once by kernel, reused for all
 * revocation passes. Do NOT munmap this.
 */
static void* persistent_sealing_bitmap_copy = NULL;

static void
app_quarantine_revoke_async(void)
{
	(void)cheri_revoke(CHERI_REVOKE_ASYNC, epoch_count, NULL);
	if(is_revoking){
		if (cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch_count)) {
			revoke_count++;
			epoch_count = cri->epochs.dequeue;

			/*
			 * Get the sealing bitmap copy. The kernel now maintains a
			 * persistent mapping that is reused across revocation passes.
			 * We cache the pointer locally to avoid repeated syscalls.
			 */
			if (persistent_sealing_bitmap_copy == NULL) {
				if (cheri_revoke_get_shadow(CHERI_CC_SEALING_BITMAP_COPY, NULL,
					&persistent_sealing_bitmap_copy) != 0) {
					mrs_puts("error getting sealing bitmap copy cap\n");
					exit(7);
				}
			}

			/*
			 * XOR to clear revoked bits from sealing bitmap.
			 * Skip zero words for efficiency.
			 */
			for(int i = 0; i < global_sealing_bitmap_size/8; i++){
				u_int64_t copy_word = ((u_int64_t*)persistent_sealing_bitmap_copy)[i];
				if (copy_word != 0) {
					((u_int64_t*)global_sealing_bitmap)[i] ^= copy_word;
				}
			}

#ifdef BITMAP_ALLOCATOR_ACTIVATE
			bitmap_otype_free_many(bitmap_otypes_ptr, (uint64_t *)persistent_sealing_bitmap_copy);
#else
			int uh_is_heap_alloc = cheri_otypes_ptr!=&cheri_otypes;
			free_many_unr(&cheri_otypes_ptr, (u_int64_t *)persistent_sealing_bitmap_copy, uh_is_heap_alloc);
#endif

			/*
			 * Don't munmap - the mapping is persistent and will be
			 * reused for subsequent revocation passes.
			 */
			is_revoking = false;
		}
		return;
	}
	is_revoking = true;
}

/*
 * Handle a malloc_revoke_quarantine_force_flush() call when operating in async mode.
 * Perform synchronous revocation for all quarantine arenas, and then revoke
 * the currently active arena.
 */
static void
malloc_revoke_quarantine_force_flush_async(void)
{
	app_quarantine_revoke_async();
}

#if defined(PRINT_CAPREVOKE) || defined(PRINT_CAPREVOKE_MRS)
static inline uint64_t
cheri_revoke_get_cyc(void)
{
#if defined(__riscv)
	return (__builtin_readcyclecounter());
#elif defined(__aarch64__)
	uint64_t _val;
	__asm __volatile("mrs %0, cntvct_el0" : "=&r" (_val));
	return (_val);
#else
	return (0);
#endif
}
#endif

#if defined(PRINT_CAPREVOKE)
static inline void
print_cheri_revoke_stats(char *what, struct cheri_revoke_syscall_info *crsi,
    uint64_t cycles)
{
	mrs_printf("mrs caprevoke %s:"
	    " efin=%" PRIu64

	    " psro=%" PRIu32
	    " psrw=%" PRIu32

	    " pfro=%" PRIu32
	    " pfrw=%" PRIu32

	    " pclg=%" PRIu32

	    " pskf=%" PRIu32
	    " pskn=%" PRIu32
	    " psks=%" PRIu32

	    " cfnd=%" PRIu32
	    " cfrv=%" PRIu32

	    " cnuk=%" PRIu32

	    " lscn=%" PRIu32
	    " pmkc=%" PRIu32

	    " pcyc=%" PRIu64
	    " fcyc=%" PRIu64
	    " tcyc=%" PRIu64
	    "\n",

	    what,
	    crsi->epochs.dequeue,

	    crsi->stats.pages_scan_ro,
	    crsi->stats.pages_scan_rw,

	    crsi->stats.pages_faulted_ro,
	    crsi->stats.pages_faulted_rw,

	    crsi->stats.fault_visits,

	    crsi->stats.pages_skip_fast,
	    crsi->stats.pages_skip_nofill,
	    crsi->stats.pages_skip,

	    crsi->stats.caps_found,
	    crsi->stats.caps_found_revoked,

	    crsi->stats.caps_cleared,

	    crsi->stats.lines_scan,
	    crsi->stats.pages_mark_clean,

	    crsi->stats.page_scan_cycles,
	    crsi->stats.fault_cycles,
	    cycles);
}
#endif /* PRINT_CAPREVOKE */

/*
 * Perform revocation then iterate through the quarantine and free entries with
 * non-zero underlying size (offload thread sets unvalidated caps to have zero
 * size).
 *
 * Supports ablation study knobs.
 */
static void
quarantine_revoke(void)
{
	/* Don't read epoch until all bitmap painting is done. */
	atomic_thread_fence(memory_order_acq_rel);
	cheri_revoke_epoch_t start_epoch = cri->epochs.enqueue;

	MRS_UTRACE(UTRACE_MRS_QUARANTINE_REVOKE, NULL, 0, 0, NULL);
	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, start_epoch)) {
# ifdef PRINT_CAPREVOKE
		struct cheri_revoke_syscall_info crsi = { 0 };
		uint64_t cyc_init, cyc_fini;

		cyc_init = cheri_revoke_get_cyc();
		(void)cheri_revoke(CHERI_REVOKE_TAKE_STATS, epoch, &crsi);
		cyc_fini = cheri_revoke_get_cyc();
		print_cheri_revoke_stats("load-barrier", &crsi,
		    cyc_fini - cyc_init);

		cyc_init = cheri_revoke_get_cyc();
		(void)cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS, epoch,
		    &crsi);
		cyc_fini = cheri_revoke_get_cyc();
		print_cheri_revoke_stats("load-final", &crsi,
		    cyc_fini - cyc_init);

# else /* PRINT_CAPREVOKE */
		(void)cheri_revoke(CHERI_REVOKE_TAKE_STATS, start_epoch, NULL);
		(void)cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS,
		    start_epoch, NULL);
		mrs_printf("epoch count: %lu, cri epoch: %lu\n", start_epoch, cri->epochs.dequeue);

# endif /* !PRINT_CAPREVOKE */
	}
	MRS_UTRACE(UTRACE_MRS_QUARANTINE_REVOKE_DONE, NULL, 0, 0, NULL);
}

static void
_internal_quarantine_flush()
{
#ifdef OFFLOAD_QUARANTINE

#ifdef PRINT_CAPREVOKE_MRS
	mrs_puts("malloc_revoke_quarantine_force_flush (offload): "
	    "waiting for offload_quarantine to drain\n");
#endif

	mrs_lock(&offload_quarantine_lock);
	while (offload_quarantine.list != NULL) {
		if (pthread_cond_wait(&offload_quarantine_empty,
		    &offload_quarantine_lock)) {
			mrs_puts("pthread error\n");
			exit(7);
		}
	}

#ifdef PRINT_CAPREVOKE_MRS
	mrs_puts("malloc_revoke_quarantine_force_flush (offload): offload_quarantine drained\n");
	mrs_printf("malloc_revoke_quarantine_force_flush: cycle count after waiting on offload %" PRIu64 "\n",
	    cheri_revoke_get_cyc());
#endif /* PRINT_CAPREVOKE_MRS */

#ifdef SNMALLOC_FLUSH
	/* Consume pending messages now in our queue. */
	snmalloc_flush_message_queue();
#endif

#ifdef PRINT_CAPREVOKE_MRS
	mrs_printf("malloc_revoke_quarantine_force_flush: cycle count after waiting on offload %" PRIu64 "\n",
	    cheri_revoke_get_cyc());
#endif

#ifdef SNMALLOC_PRINT_STATS
	snmalloc_print_stats();
#endif

	mrs_unlock(&offload_quarantine_lock);
	if (pthread_cond_signal(&offload_quarantine_ready)) {
		mrs_puts("pthread error\n");
		exit(7);
	}

#else /* OFFLOAD_QUARANTINE */

#ifdef PRINT_CAPREVOKE_MRS
	mrs_puts("malloc_revoke_quarantine_force_flush\n");
#endif
	quarantine_revoke();
#ifdef SNMALLOC_FLUSH
	/* Consume pending messages now in our queue. */
	snmalloc_flush_message_queue();
#endif
#if defined(SNMALLOC_PRINT_STATS)
	snmalloc_print_stats();
#endif

#endif /* OFFLOAD_QUARANTINE */
}

int
malloc_revoke_quarantine_force_flush(void)
{
	return ENOTSUP;
	if (!quarantining)
		return (ENOTSUP);
	MRS_UTRACE(UTRACE_MRS_MALLOC_REVOKE_QUARANTINE_FORCE_FLUSH, NULL, 0,
	    0, NULL);

	if (1) {
		malloc_revoke_quarantine_force_flush_async();
	} else {
		_internal_quarantine_flush();
	}
	return (0);
}

bool
malloc_revoke_enabled(void)
{
	return (quarantining);
}

void
malloc_revoke(void)
{
	(void)malloc_revoke_quarantine_force_flush();
}

bool
malloc_is_revoking(void)
{
	return (quarantining);
}

/*
 * Check whether we should flush based on the quarantine policy and perform the
 * flush if so.  Takes into account whether offload is enabled or not.
 *
 * In the wrapper, we perform these checks at the beginning of allocation
 * routines (so that the allocation routines might use the revoked memory in
 * the non-offload edge case where this could happen) rather than during an
 * mmap call - it might be better to perform this check just as the allocator
 * runs out of memory and before it calls mmap, but this is not possible from
 * the wrapper.
 */

static inline bool otypes_should_flush(){
#ifdef BITMAP_ALLOCATOR_ACTIVATE
	return bitmap_otypes_ptr->busy >= (u_int)cheri_otypes_threshold;
#else
	return cheri_otypes_ptr->busy >= cheri_otypes_threshold;
#endif
}

static inline void
check_and_perform_flush()
{
	/*
	 * Do an unlocked check and bail quickly if the quarantine
	 * does not require flushing.
	 */
	if (!otypes_should_flush())
		return;
#ifdef BITMAP_ALLOCATOR_ACTIVATE
	mrs_debug_printf("check_and_perform_flush: otypes busy %d >= threshold %d\n",
	    bitmap_otypes_ptr->busy, cheri_otypes_threshold);
#else
	mrs_debug_printf("check_and_perform_flush: otypes busy %d >= threshold %d\n",
	    cheri_otypes_ptr->busy, cheri_otypes_threshold);
#endif
	/* Attempt to acquire the lock without blocking. */
	if (!mrs_trylock(&mrs_revoke_lock)) {
		return;
	}

	if (!otypes_should_flush()) {
		mrs_unlock(&mrs_revoke_lock);
		return;
	}

	app_quarantine_revoke_async();
	mrs_unlock(&mrs_revoke_lock);
}

/* constructor and destructor */

#ifdef OFFLOAD_QUARANTINE
static void
spawn_background(void)
{
	initialize_lock(offload_quarantine_lock);

	/*
	 * Fire a spurious signal at the condvars now in an attempt to force
	 * the pthread machinery to initialize them fully now, before the
	 * application has a chance to start up and fill quarantine.  Otherwise
	 * there's a chance that we'll attempt allocation while signaling the
	 * need for revocation during allocation (thereby deadlocking an
	 * application thread against itself) or while signaling that the
	 * quarantine is empty (thereby deadlocking the offload thread against
	 * itself).
	 */
	pthread_cond_signal(&offload_quarantine_empty);
	pthread_cond_signal(&offload_quarantine_ready);

	pthread_t thd;
	if (pthread_create(&thd, NULL, mrs_offload_thread, NULL)) {
		mrs_puts("pthread error\n");
		exit(7);
	}
}
#endif /* OFFLOAD_QUARANTINE */

static void
mrs_init_impl_locked(void)
{
	initialize_lock(app_quarantine_lock);
	initialize_lock(mrs_revoke_lock);
	initialize_lock(printf_lock);

#ifdef OFFLOAD_QUARANTINE
	spawn_background();
	pthread_atfork(NULL, NULL, spawn_background);
#endif /* OFFLOAD_QUARANTINE */

#ifdef MRS_PINNED_CPUSET
#ifdef __aarch64__
	cpuset_t mask = {0};
	if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
	    (id_t)-1, sizeof(mask), &mask) != 0) {
		mrs_puts("cpuset_getaffinity failed\n");
		exit(7);
	}

	if (CPU_ISSET(2, &mask)) {
		CPU_CLR(2, &mask);
		if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
		    (id_t)-1, sizeof(mask), &mask) != 0) {
			mrs_puts("cpuset_setaffinity failed\n");
			exit(7);
		}
	}
#endif
#endif

	page_size = getpagesize();
	if ((page_size & (page_size - 1)) != 0) {
		mrs_puts("page_size not a power of 2\n");
		exit(7);
	}

	char *envstr, *end;
	if ((envstr = secure_getenv(MALLOC_QUARANTINE_DENOMINATOR_ENV)) !=
	    NULL) {
		errno = 0;
		quarantine_denominator = strtoul(envstr, &end, 0);
		if (*end != '\0' ||
		    (quarantine_denominator == ULONG_MAX &&
		     errno == ERANGE)) {
			mrs_puts("invalid "
			    MALLOC_QUARANTINE_DENOMINATOR_ENV "\n");
			exit(7);
		}
	}
	if ((envstr = secure_getenv(MALLOC_QUARANTINE_NUMERATOR_ENV)) !=
	    NULL) {
		errno = 0;
		quarantine_numerator = strtoul(envstr, &end, 0);
		if (*end != '\0' ||
		    (quarantine_numerator == ULONG_MAX &&
		     errno == ERANGE)) {
			mrs_puts("invalid "
			    MALLOC_QUARANTINE_NUMERATOR_ENV "\n");
			exit(7);
		}
	}
	if (quarantine_denominator == 0) {
		mrs_puts("quarantine_denominator can not be 0\n");
		exit(7);
	}
	if (quarantine_denominator > 256) {
		/* Could overflow with 56-bits of userspace addresses */
		mrs_puts("quarantine_denominator > 256\n");
		exit(7);
	}
	if (quarantine_numerator == 0) {
		mrs_puts("quarantine_numerator can not be 0\n");
		exit(7);
	}
	if (quarantine_numerator > 256) {
		/* Could overflow with 56-bits of userspace addresses */
		mrs_puts("quarantine_numerator > 256\n");
		exit(7);
	}

	if (!issetugid()) {
		mrs_utrace = (getenv(MRS_UTRACE_ENV) != NULL);
	}

	uint32_t bsdflags;

	if (_elf_aux_info(AT_BSDFLAGS, &bsdflags, sizeof(bsdflags)) == 0) {
		quarantining = ((bsdflags & ELF_BSDF_CHERI_REVOKE) != 0);
		revoke_every_free =
		    ((bsdflags & ELF_BSDF_CHERI_REVOKE_EVERY_FREE) != 0);
		revoke_async = ((bsdflags & ELF_BSDF_CHERI_REVOKE_ASYNC) != 0);
	}

	if (!issetugid()) {
		if (getenv(MALLOC_QUARANTINE_DISABLE_ENV) != NULL) {
			quarantining = false;
		} else if (getenv(MALLOC_QUARANTINE_ENABLE_ENV) != NULL) {
			quarantining = true;
		}

		if (getenv(MALLOC_ABORT_DISABLE_ENV) != NULL)
			abort_on_validation_failure = false;
		else if (getenv(MALLOC_ABORT_ENABLE_ENV) != NULL)
			abort_on_validation_failure = true;

		if (getenv(MALLOC_REVOKE_EVERY_FREE_DISABLE_ENV) != NULL)
			revoke_every_free = false;
		else if (getenv(MALLOC_REVOKE_EVERY_FREE_ENABLE_ENV) != NULL)
			revoke_every_free = true;

#ifndef OFFLOAD_QUARANTINE
		if (getenv(MALLOC_REVOKE_SYNC_ENV) != NULL)
			revoke_async = false;
		else if (getenv(MALLOC_REVOKE_ASYNC_ENV) != NULL)
			revoke_async = true;
#endif

		if (getenv(MALLOC_BOUND_CHERI_POINTERS) != NULL)
			bound_pointers = true;
		else if (getenv(MALLOC_NOBOUND_CHERI_POINTERS) != NULL)
			bound_pointers = false;
	}
	if (!quarantining)
		goto nosys;
    
	if(!global_cheri_otypes_initialized) {
		if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
			(void **)&cri) != 0) {
			if (errno == ENOSYS) {
				quarantining = false;
				goto nosys;
			}
			mrs_puts("error getting kernel caprevoke counters\n");
			exit(7);
		}
		if (cheri_revoke_get_shadow(CHERI_CC_SEALING_BITMAP, NULL,
			&global_sealing_bitmap) != 0) {
			mrs_puts("error getting sealing bitmap cap\n");
			exit(7);
		}
		global_sealing_bitmap_size = __builtin_cheri_length_get(global_sealing_bitmap);
#ifdef BITMAP_ALLOCATOR_ACTIVATE
		global_cheri_otypes_initialized = true;
#else
		/* Use shared global cheri_otypes from u_subr_unit */
	
		cheri_otypes_ptr = get_global_cheri_otypes();
#endif
	}



nosys:
	mrs_initialized = true;
	/*
	//claim the reserved otypes, 0x3fffc to 0x3ffff are reserved 
	alloc_unr_specific(cheri_otypes, 0x3fffc);
	alloc_unr_specific(cheri_otypes, 0x3fffd);
	alloc_unr_specific(cheri_otypes, 0x3fffe);
	alloc_unr_specific(cheri_otypes, 0x3ffff);
	*/

#if defined(PRINT_CAPREVOKE) || defined(PRINT_CAPREVOKE_MRS) || defined(PRINT_STATS)
	mrs_puts(VERSION_STRING);
#endif
}

static void
mrs_init_impl(void)
{
	MRS_LOCK(&mrs_init_lock);
	if (!mrs_initialized)
		mrs_init_impl_locked();
	MRS_UNLOCK(&mrs_init_lock);
}

static __attribute__((always_inline)) void
mrs_init(void)
{
	if (__predict_false(!mrs_initialized))
		mrs_init_impl();
	/* Invariant: mrs_init_impl must initialize mrs or exit. */
	assert(mrs_initialized);
}

__attribute__((__constructor__(100)))
static void
mrs_constructor(void)
{
	mrs_init();
}

__attribute__((destructor))
static void mrs_destructor(void)
{
	if(getenv("CC_DEBUG")!=NULL){
		mrs_printf("revoke counter: %d\n", revoke_count);
		mrs_printf("alloc counter: %d\n", malloc_count);
#ifdef BITMAP_ALLOCATOR_ACTIVATE
		mrs_printf("Bitmap mem usage: %zu\n", bitmap_otype_mem_usage(bitmap_otypes_ptr));
#else
#endif
	}
}

#ifdef PRINT_STATS
__attribute__((destructor))
static void
fini(void)
{
#ifdef OFFLOAD_QUARANTINE
	mrs_printf("fini: heap size %zu, max heap size %zu, offload quarantine size %zu, max offload quarantine size %zu\n",
	    allocated_size, max_allocated_size, offload_quarantine.size,
	    offload_quarantine.max_size);
#else /* OFFLOAD_QUARANTINE */
	mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n",
	    allocated_size, max_allocated_size, app_quarantine->size,
	    app_quarantine->max_size);
#endif /* !OFFLOAD_QUARANTINE */
}
#endif /* PRINT_STATS */

/* Colored capabilities*/
static inline void* cc_set_objectid(void* p){
#ifdef BITMAP_ALLOCATOR_ACTIVATE
	int otype = bitmap_otype_alloc(bitmap_otypes_ptr);
	while(otype<0){
		check_and_perform_flush();
		otype = bitmap_otype_alloc(bitmap_otypes_ptr);
	}
#else
	int otype = alloc_unr(cheri_otypes_ptr);
	while(otype<0){
		check_and_perform_flush();
		otype = alloc_unr(cheri_otypes_ptr);
	}
#endif
	malloc_count++;
	assert(otype >= 0);
    p = __builtin_cheri_cc_set_type(p, otype);
    p = cheri_andperm(p, ~CHERI_PERM_SW_VMEM);
	return p;
}

/* mrs functions */

static void *
mrs_real_malloc(size_t size)
{
	return (mrs_bound_pointer(REAL(malloc)(size), size));
}

static void *
mrs_malloc(size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_malloc(size));

	/*mrs_debug_printf("mrs_malloc: called\n");*/

	check_and_perform_flush();

	void *allocated_region;

	/*
	 * Round up here to make sure there is only one allocation per
	 * granule without requiring modifications to the underlying
	 * allocator.
	 *
	 * XXX: If an allocator produced special, non-writable capabilities
	 * for size=0 we might want to pass those calls through, but none
	 * of the currently supported allocators do.
	 */

	if (size < CAPREVOKE_BITMAP_ALIGNMENT)
		allocated_region = mrs_real_malloc(CAPREVOKE_BITMAP_ALIGNMENT);
	else
		allocated_region = mrs_real_malloc(size);
	
	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_MALLOC, NULL, size, 0,
		    allocated_region);
		return (allocated_region);
	}



#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

	/*mrs_debug_printf("mrs_malloc: called size 0x%zx, allocation %#p\n",
	    size, allocated_region);*/

	allocated_region = cc_set_objectid(allocated_region);

	MRS_UTRACE(UTRACE_MRS_MALLOC, NULL, size, 0, allocated_region);
	return (allocated_region);
}



int malloc2(size_t size)
{
	int otype;
	if(size == 0){
#ifdef BITMAP_ALLOCATOR_ACTIVATE
		return bitmap_otypes_ptr->busy;
#else
		return cheri_otypes_ptr->busy;
#endif
		otype = alloc_unr(cheri_otypes_ptr);
	}else{
#ifdef BITMAP_ALLOCATOR_ACTIVATE
		otype = bitmap_otype_alloc_specific(bitmap_otypes_ptr, size);
#else
		otype = alloc_unr_specific(cheri_otypes_ptr, size);
#endif
	}
	assert(otype);
	return (otype);
}

static void *
mrs_real_calloc(size_t number, size_t size)
{
	return (mrs_bound_pointer(REAL(calloc)(number, size), number * size));
}


void* mrs_calloc_unr(size_t number, size_t size)
{
	size_t tmpsize;

	mrs_init();

	if (!quarantining)
		return (mrs_real_calloc(number, size));

	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: called\n");*/

	void *allocated_region;

	/*
	 * Round up here to make sure there is only one allocation per
	 * granule without requiring modifications to the underlying
	 * allocator.
	 *
	 * XXX: it's conceviable the underlying allocator could reduce
	 * the alignment requirement for small sizes but that seems like an
	 * extraordinarily unlikely and highly questionable optimization.
	 */
	if (!__builtin_mul_overflow(number, size, &tmpsize) &&
	    tmpsize < CAPREVOKE_BITMAP_ALIGNMENT)
		allocated_region = mrs_real_calloc(1, CAPREVOKE_BITMAP_ALIGNMENT);
	else
		allocated_region = mrs_real_calloc(number, size);
	

	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number,
		    allocated_region);
		return (allocated_region);
	}



	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);*/
	
	MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number, allocated_region);
	return (allocated_region);
}

void *
mrs_calloc(size_t number, size_t size)
{
	size_t tmpsize;

	mrs_init();

	if (!quarantining)
		return (mrs_real_calloc(number, size));

	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: called\n");*/

	check_and_perform_flush();

	void *allocated_region;

	/*
	 * Round up here to make sure there is only one allocation per
	 * granule without requiring modifications to the underlying
	 * allocator.
	 *
	 * XXX: it's conceviable the underlying allocator could reduce
	 * the alignment requirement for small sizes but that seems like an
	 * extraordinarily unlikely and highly questionable optimization.
	 */
	if (!__builtin_mul_overflow(number, size, &tmpsize) &&
	    tmpsize < CAPREVOKE_BITMAP_ALIGNMENT)
		allocated_region = mrs_real_calloc(1, CAPREVOKE_BITMAP_ALIGNMENT);
	else
		allocated_region = mrs_real_calloc(number, size);
	

	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number,
		    allocated_region);
		return (allocated_region);
	}



	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);*/
	allocated_region = cc_set_objectid(allocated_region);
	
	MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number, allocated_region);
	return (allocated_region);
}

static int
mrs_real_posix_memalign(void **ptr, size_t alignment, size_t size)
{
	int ret;

	ret = REAL(posix_memalign)(ptr, alignment, size);
	if (ret == 0)
		*ptr = mrs_bound_pointer(*ptr, size);
	return (ret);
}

static int
mrs_posix_memalign(void **ptr, size_t alignment, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_posix_memalign(ptr, alignment, size));

	mrs_debug_printf("mrs_posix_memalign: called ptr %p alignment %zu size %zu\n",
	    ptr, alignment, size);

	check_and_perform_flush();

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT)
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;

	int ret = mrs_real_posix_memalign(ptr, alignment, size);
	if (ret != 0) {
		return (ret);
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(*ptr, cheri_getlen(*ptr));
#endif /* CLEAR_ON_ALLOC */

	*ptr = cc_set_objectid(*ptr);


	MRS_UTRACE(UTRACE_MRS_POSIX_MEMALIGN, NULL, size, alignment, *ptr);
	return (ret);
}

static void *
mrs_real_aligned_alloc(size_t alignment, size_t size)
{
	return (mrs_bound_pointer(REAL(aligned_alloc)(alignment, size), size));
}

static void *
mrs_aligned_alloc(size_t alignment, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_aligned_alloc(alignment, size));

	mrs_debug_printf("mrs_aligned_alloc: called alignment %zu size %zu\n",
	    alignment, size);

	check_and_perform_flush();

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT)
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;

	void *allocated_region = mrs_real_aligned_alloc(alignment, size);
	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_ALIGNED_ALLOC, NULL, size, alignment,
		    allocated_region);
		return (allocated_region);
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

	allocated_region = cc_set_objectid(allocated_region);

	MRS_UTRACE(UTRACE_MRS_ALIGNED_ALLOC, NULL, size, alignment,
	    allocated_region);
	return (allocated_region);
}

static void *
mrs_real_realloc(void *ptr, size_t size)
{
	return (mrs_bound_pointer(REAL(realloc)(ptr, size), size));
}

/*
 * Replace realloc with a malloc and free to avoid dangling pointers
 * in case of in-place realloc that shrinks the buffer.  If ptr is not
 * a real allocation, its buffer will still get copied into a new
 * allocation.
 */
static void *
mrs_realloc(void *ptr, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_realloc(ptr, size));

	size_t old_size = cheri_getlen(ptr);
	mrs_debug_printf("mrs_realloc: called ptr %p ptr size %zu new size %zu\n",
	    ptr, old_size, size);

	/*
	 * If the new size fits in the current allocation and we won't
	 * be wasting too much space, just return the existing pointer.
	 *
	 * Only try to reclaim space by copying if we'd recover at least
	 * half of the allocated storage.  In other cases we can't tell
	 * the difference between shrinking and linear growth into a
	 * large over-allocation (e.g., growing into snmalloc's
	 * power-of-two buckets by 1K) and we especially want to avoid
	 * copying such cases.
	 */
	if (ptr != NULL && cheri_gettag(ptr) && cheri_getoffset(ptr) == 0 &&
	    size <= old_size && old_size - size <= (old_size >> 1))
		return (ptr);

	void *new_alloc = mrs_malloc(size);

	/*
	 * Per the C standard, copy and free IFF the old pointer is valid
	 * and allocation succeeds.
	 */
	if (ptr != NULL && new_alloc != NULL) {
		memcpy(new_alloc, ptr, size < old_size ? size : old_size);
		mrs_free(ptr);
	}
	MRS_UTRACE(UTRACE_MRS_REALLOC, ptr, size, 0, new_alloc);
	return (new_alloc);
}

static void
mrs_free(void *ptr)
{
	void *ins;

	assert(mrs_initialized || ptr == NULL);

	if (!quarantining)
		return (REAL(free)(ptr));

	/*mrs_debug_printf("mrs_free: called address %p\n", ptr);*/

	MRS_UTRACE(UTRACE_MRS_FREE, ptr, 0, 0, 0);

	if (ptr == NULL)
		return;

	/*
	 * If not offloading, validate the passed-in cap here and
	 * replace it with the cap to its underlying allocation.
	 */
#ifdef OFFLOAD_QUARANTINE
	ins = ptr
#else
	ins = validate_freed_pointer(ptr);
	if (ins == NULL) {
		mrs_debug_printf("mrs_free: validation failed\n");
		if (abort_on_validation_failure)
			abort();
		else
			return;
	}
	
	(REAL(free)(ins));

#endif /* !OFFLOAD_QUARANTINE */

#ifdef CLEAR_ON_FREE
	bzero(cheri_setoffset(ptr, 0), cheri_getlen(ptr));
#endif
	return;
}

static void *
mrs_real_mallocx(size_t size, int flags)
{
	return (mrs_bound_pointer(REAL(mallocx)(size, flags), size));
}

void *
mrs_mallocx(size_t size, int flags)
{
	size_t align = MALLOCX_ALIGN_GET(flags);
	void *ret;

	mrs_init();

	if (!quarantining)
		return (mrs_real_mallocx(size, flags));

	if (align <= CAPREVOKE_BITMAP_ALIGNMENT)
		ret = mrs_malloc(size);
	else if (mrs_posix_memalign(&ret, size, align) != 0)
		ret = NULL;

#ifndef CLEAR_ON_ALLOC
	/* Clear if requested and we aren't clearing above. */
	if (ret != NULL && (flags & MALLOCX_ZERO) != 0)
		clear_region(ret, cheri_getlen(ret));
#endif
	return (ret);
}

static void *
mrs_real_rallocx(void *ptr, size_t size, int flags)
{
	return (mrs_bound_pointer(REAL(rallocx)(ptr, size, flags), size));
}

void *
mrs_rallocx(void *ptr, size_t size, int flags)
{
	void *new_alloc;
	size_t old_size;

	mrs_init();

	if (!quarantining)
		return (mrs_real_rallocx(ptr, size, flags));

	old_size = cheri_getlen(ptr);

	mrs_debug_printf("%s: called ptr %p ptr size %zu new size %zu\n",
	    __func__, ptr, old_size, size);

	/*
	 * Allocate an appropriately-aligned, potentially-zeroed space.
	 * In principle might be more efficent to only zero the end, but
	 * this isn't a widly used API so just waste a little memory
	 * bandwidth to make things similar.
	 */
	new_alloc = mrs_mallocx(size, flags);

	/*
	 * Per the C standard, copy and free IFF the old pointer is valid
	 * and allocation succeeds.
	 */
	if (ptr != NULL && new_alloc != NULL) {
		memcpy(new_alloc, ptr, size < old_size ? size : old_size);
		mrs_free(ptr);
	}
	MRS_UTRACE(UTRACE_MRS_REALLOC, ptr, size, 0, new_alloc);
	return (new_alloc);
}

void
mrs_dallocx(void *ptr, int flags)
{
	/* XXX: snmalloc just ignores flags.  */
	mrs_free(ptr);
}

void
mrs_sdallocx(void *ptr, size_t size, int flags)
{
	/*
	 * XXX: snmalloc just frees ignoring flags so do the same for
	 * simplicity.
	 */
	mrs_free(ptr);
}

#ifdef OFFLOAD_QUARANTINE
static void *
mrs_offload_thread(void *arg)
{
#ifdef PRINT_CAPREVOKE_MRS
	mrs_printf("offload thread spawned: %d\n", pthread_getthreadid_np());
#endif

#ifdef MRS_PINNED_CPUSET
#ifdef __aarch64__
	cpuset_t mask = {0};
	if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
	    (id_t)-1, sizeof(mask), &mask) != 0) {
		mrs_puts("cpuset_getaffinity failed\n");
		exit(7);
	}

	if (CPU_ISSET(3, &mask)) {
		CPU_CLR(3, &mask);
		if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
		    (id_t)-1, sizeof(mask), &mask) != 0) {
			mrs_puts("cpuset_setaffinity failed\n");
			exit(7);
		}
	}
#endif
#endif

	/*
	 * Perform a spurious allocation here to force the allocator to wake
	 * initialize any thread-local state associated with this thread.
	 * Do this bypassing the quarantine logic, so that we don't get into
	 * any stickier mess than we're already in.
	 */
	void *p = REAL(malloc)(1);

	mrs_lock(&offload_quarantine_lock);
	for (;;) {
		while (offload_quarantine.list == NULL) {
#ifdef PRINT_CAPREVOKE_MRS
			mrs_puts("mrs_offload_thread: waiting for offload_quarantine to be ready\n");
#endif /* PRINT_CAPREVOKE_MRS */
			if (pthread_cond_wait(&offload_quarantine_ready,
			    &offload_quarantine_lock) != 0) {
				mrs_puts("pthread error\n");
				exit(7);
			}
		}
#ifdef PRINT_CAPREVOKE_MRS
		mrs_debug_printf("mrs_offload_thread: offload_quarantine ready\n");
#endif /* PRINT_CAPREVOKE_MRS */

		/*
		 * Re-calculate the quarantine's size using only valid
		 * descriptors.
		 */
		offload_quarantine.size = 0;

		/*
		 * Iterate through the quarantine validating the freed
		 * pointers.
		 */
		for (struct mrs_descriptor_slab *iter = offload_quarantine.list;
		     iter != NULL; iter = iter->next) {
			for (int i = 0; i < iter->num_descriptors; i++) {
				iter->slab[i].ptr =
				    validate_freed_pointer(iter->slab[i].ptr);

				if (iter->slab[i].ptr != NULL) {
					offload_quarantine.size +=
					    iter->slab[i].size;
				}
			}
		}

		mrs_debug_printf("mrs_offload_thread: flushing validated quarantine size %zu\n", offload_quarantine.size);

		quarantine_revoke();

#ifdef PRINT_CAPREVOKE_MRS
		mrs_printf("mrs_offload_thread: application quarantine's (unvalidated) size "
		    "when offloaded quarantine flush complete: %zu\n",
		    app_quarantine->size);
#endif /* PRINT_CAPREVOKE_MRS */

		if (pthread_cond_signal(&offload_quarantine_empty) != 0) {
			mrs_puts("pthread error\n");
			exit(7);
		}
	}
}
#endif /* OFFLOAD_QUARANTINE */
