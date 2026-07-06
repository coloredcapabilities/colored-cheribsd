#include <sys/sysent.h>
#include <sys/proc.h>
#include <vm/cc_revoke.h>
#include <vm/vm_cheri_revoke.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/swap_pager.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

 /*
 * Colored-Cap modifications: 
 *      Author: Ruben Sturm, Merve Gulmez
 *      Copyright (c) 2025 Ericsson AB 
 */


/*
 * Unmap the persistent sealing bitmap copy mapping for a process.
 * Called on exec (after vmspace_exec replaces the address space) and on exit,
 * so the per-process mapping allocated by vm_cheri_revoke_sealing_bitmap_copy
 * is not leaked.  Must be called before the vmspace is torn down.
 */
void
cc_dealloc_sealing_bitmap(struct proc *p)
{
	vm_map_t map;
	vm_pointer_t addr;

	if (p->cheri_cc_sealing_base_copy == 0)
		return;

	addr = p->cheri_cc_sealing_base_copy;
	p->cheri_cc_sealing_base_copy = 0;

	map = &p->p_vmspace->vm_map;
	(void)vm_map_remove(map, addr, addr + SEALING_BITMAP_SIZE);
}

int vm_map_install_cc_sealing_bitmap(struct vm_map *map, struct sysentvec *sv)
{
	int cow = MAP_CREATE_SHADOW;
	int error = KERN_SUCCESS;
	bool reserved_sealing_bitmap = false;
	bool reserved_info = false;
	vm_object_t vmo_sealing, vmo_info;
	vm_pointer_t start;

	vm_offset_t start_addr = sv->sv_cheri_cc_sealing_base;
	vm_offset_t end_addr = start_addr + SEALING_BITMAP_SIZE;

	vmo_sealing = vm_object_allocate(OBJT_SWAP, end_addr - start_addr);

	vm_object_set_flag(vmo_sealing, OBJ_NOCAP);

	vmo_info = vm_object_allocate(OBJT_SWAP, PAGE_SIZE);

	vm_map_lock(map);

	start = start_addr; /* upcast to NULL-derived cap */

	error = vm_map_reservation_create_locked(map, &start,
	    end_addr - start_addr, VM_PROT_READ | VM_PROT_WRITE);

	KASSERT((ptraddr_t)start == start_addr,
	    ("vm_map_reservation_create_locked moved revocation's cheese"));

	if (error != KERN_SUCCESS)
		goto out;

	reserved_sealing_bitmap = true;

	error = vm_map_insert(map, vmo_sealing, 0, start, end_addr,
	    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
	    cow, start_addr);

	if (error != KERN_SUCCESS)
		goto out;

	/* Now do the same thing for the info page */
	start_addr = start = sv->sv_cheri_revoke_info_page;
	end_addr = sv->sv_cheri_revoke_info_page + PAGE_SIZE;

	error = vm_map_reservation_create_locked(map, &start,
	    end_addr - start_addr,
	    VM_PROT_READ | VM_PROT_WRITE);
	reserved_info = true;

	KASSERT((ptraddr_t)start == start_addr,
	    ("vm_map_reservation_create_locked moved revocation's cheese"));

	if (error != KERN_SUCCESS)
		goto out;

	error = vm_map_insert(map, vmo_info, 0, start, end_addr,
	    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
	    0, start_addr);

	if (error != KERN_SUCCESS)
		goto out;

out:
	if (error != KERN_SUCCESS) {
		int error2 __diagused;

		if (reserved_info) {
			error2 = vm_map_reservation_delete_locked(map,
			    sv->sv_cheri_revoke_info_page);
			KASSERT(error2 == KERN_SUCCESS,
			    ("vm_map_install_cc_sealing_bitmap can't undo"));
		}
		if (reserved_sealing_bitmap) {
			error2 = vm_map_reservation_delete_locked(map,
			    sv->sv_cheri_cc_sealing_base);
			KASSERT(error2 == KERN_SUCCESS,
			    ("vm_map_install_cc_sealing_bitmap can't undo"));
		}
	}

	vm_map_unlock(map);

	if (error == KERN_SUCCESS) {
		/* Initialize cheri_revoke info (map unlocked for copyout) */
		struct cheri_revoke_info initinfo = {
			.base_mem_nomap =
			    sv->sv_cheri_cc_sealing_base +
			    SEALING_BITMAP_SIZE,
			.base_otype =
			    sv->sv_cheri_cc_sealing_base +
			    SEALING_BITMAP_SIZE -
			    VM_CHERI_REVOKE_BSZ_OTYPE,
			{0, 0}
		};
		struct cheri_revoke_info_page * __capability infopage;
		vm_cheri_revoke_info_page(map, sv, &infopage);

		error = copyout(&initinfo, infopage, sizeof(initinfo));
		KASSERT(error == 0,
		    ("vm_map_install_cc_sealing_bitmap copyout"));
	} else {
		vm_object_deallocate(vmo_sealing);
		vm_object_deallocate(vmo_info);
	}

	return (error);
}