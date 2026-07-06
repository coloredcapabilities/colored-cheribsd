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


int main() {
  char test[8];
  long i = 0;
  char * ptr = &test[0];
  long otype = 0x40000; 
  long total_otype = ((1 << 21) -5);
  for (i; i < total_otype; i++) {
      ptr = __builtin_cheri_cc_set_type(ptr, otype);
      printf("otype: %llx\n", otype);
      if (__builtin_cheri_type_get(ptr) != otype) { 
        printf(" false : ccgettype: %llx\n", __builtin_cheri_type_get(ptr));
        exit(-1);
      }
      printf("ccgettype: %llx\n", __builtin_cheri_type_get(ptr));
      otype++; 
  }
}