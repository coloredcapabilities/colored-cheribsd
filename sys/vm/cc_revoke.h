#ifndef	_CC_REVOKE_
#define	_CC_REVOKE_
/*
 * Colored-Cap modifications: 
 *      Author: Ruben Sturm, Merve Gulmez
 *      Copyright (c) 2025 Ericsson AB 
 *
 */
#if __has_feature(capabilities)
#include <cheri/cherireg.h> /* For CHERI_OTYPE_BITS */
#endif
#include <sys/malloc.h>

static inline void cc_write(u_long val){
    __asm __volatile("csrw ccp, %0" :: "r" (val));
}

static inline void cc_write_threshold(u_long val){
    __asm __volatile("csrw ccpt, %0" :: "r" (val));
}

static inline u_long cc_read(void){
    u_long val;
    __asm __volatile("csrr %0, ccp" : "=r" (val));
    return val;
}
struct vm_map;
static const size_t SEALING_BITMAP_SIZE = ((1 << CHERI_OTYPE_BITS) / 8);

int vm_map_install_cc_sealing_bitmap(struct vm_map *map, struct sysentvec *sv);

void cc_dealloc_sealing_bitmap(struct proc* p);
void cc_alloc_sealing_bitmap(struct proc* p);

#endif