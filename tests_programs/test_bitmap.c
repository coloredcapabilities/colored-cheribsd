/*
* Colored-Cap modifications: 
*      Author: Ruben Sturm
*      Copyright (c) 2025 Ericsson AB 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <cheri/revoke.h>
#include <assert.h>

#define CHERI_CC_SEALING_BITMAP				0x08
static void *sealing_bitmap;
//static void *shadow_bitmap;
    /*
    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM_ENTIRE, NULL, &shadow_bitmap);
    *((int*)shadow_bitmap) = 4095;
    */

    //assert(cheri_revoke_get_shadow(CHERI_CC_SEALING_BITMAP, NULL, &sealing_bitmap)==0);
    //printf("sealingbitmap: %p\n", sealing_bitmap);

void write_sealing_bitmap(char* sbitmap, int otype, int val){
    int byte = otype/8;
    int bit = otype%8;
    if(val==1){
        sbitmap[byte] = sbitmap[byte]|((1<<bit));
    }else{
        sbitmap[byte] = sbitmap[byte]&(~(1<<bit));
    }
}


void use_after_free(int* p){
    printf("ccgettype: %llx\n", __builtin_cheri_type_get(p));
    printf("setting value of p\n");
    *p = 5;
    printf("value p:%d\n", *p);
    printf("freeing p\n");
    free(p);
    printf("setting value of p\n");
    *p = 7;
    printf("value p:%d\n", *p);
}

int main(){
    int* p1 = (int*) malloc(sizeof(int*));
    printf("value p:%d\n", *p1);
    free(p1);
    printf("Normal malloc:\n");
    malloc_revoke_quarantine_force_flush();
    int* p2 = (int*) malloc(sizeof(int*));
    printf("value p:%d\n", *p2);
    free(p2);
    use_after_free(p1);
    use_after_free(p2);
}