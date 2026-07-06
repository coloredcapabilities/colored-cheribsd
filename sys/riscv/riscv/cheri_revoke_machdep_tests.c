/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Nathaniel Filardo
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/systm.h>

#include <machine/_inttypes.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_cheri_revoke.h>
#include <vm/cc_revoke.h>

static inline unsigned
vm_cheri_revoke_test_range(vm_offset_t start, vm_offset_t end, uintcap_t cut)
{
	ptraddr_t va = cheri_getbase(cut);

	return (va >= start && va < end);
}

static inline unsigned long vm_cheri_revoke_test_mem_cc(uintcap_t cut, uint64_t sealing_bitmap){
	uint64_t otype = cheri_gettype(cut);
	if(otype >= SEALING_BITMAP_SIZE*8){
		return 0;
	}
	uint64_t byte_offset = otype/8;
	uint64_t bit_offset = otype%8;
	uint8_t* __capability sealing_bitmap_cap = cheri_capability_build_user_data(CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL, sealing_bitmap, SEALING_BITMAP_SIZE, 0);
	
	const uint8_t * __capability byte_address = sealing_bitmap_cap + byte_offset;
	int byte = fubyte(byte_address);
	if (byte == -1) {
		printf("%s: failed to read sealingbitmap for %#.16lp"
			"(s=%#.16lp); assuming not revoked!\n",
			__func__, (void * __capability)cut, byte_address);
		return (0);
	}
	byte = byte & 0xFF;
	if(byte==255){
		return (1);
	}else if(byte==0){
		return (0);
	}
	return ((byte>>bit_offset)&1);
}


static unsigned long
vm_cheri_revoke_test_cc(uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end, uint64_t sealing_bitmap)
{
	return 0;
	/*
	 * Only check the capability if it has some memory permissions.
	 */
	if ((perms & CHERI_PERMS_HWALL_MEMORY) != 0) {
		if (vm_cheri_revoke_test_range(start, end, cut))
			return (1);

		if ((perms & CHERI_PERM_SW_VMEM) == 0) {
			return vm_cheri_revoke_test_mem_cc(cut, sealing_bitmap);
		}
	}

	return (0);
}



void
vm_cheri_revoke_set_test(vm_map_t map, int flags)
{
	switch(flags) {
	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_cc;
		break;

	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_cc;
		break;

	case VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_cc;
		break;

	default:
		panic("Bad cheri_revoke cookie flags 0x%x\n", flags);
	}
}
