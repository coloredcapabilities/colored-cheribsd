/*
* Colored-Cap modifications: 
*      Author: Ruben Sturm
*      Copyright (c) 2025 Ericsson AB 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

long cc_read(void){
	long val;
	__asm __volatile("csrr %0, ccp" : "=r" (val));
	return val;
}

void cc_write(long val){
	__asm __volatile("csrw ccp, %0" :: "r" (val));
}

int main(){
    cc_write(5);
    //fork();
	printf("hello world: %d\n", cc_read());
}