/*
* Colored-Cap modifications: 
*      Author: Ruben Sturm
*      Copyright (c) 2025 Ericsson AB 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define max_otpyes 2097152
#define max_free_chance 10000

__attribute__((optnone))
void malloc_test(int alloc_size, int free_chance){
    for(int i=0;i<max_otpyes*4;i++){
        void* p = malloc(alloc_size);
        if(rand()%max_free_chance<=free_chance){
            free(p);
        }
    }
}

int main(int argc, char* argv[]){
    if(argc < 3){
        printf("please provide an alloc size and a free chance\n");
        exit(-1);
    }
    int alloc_size = atoi(argv[1]);
    int free_chance = atoi(argv[2]);
    malloc_test(alloc_size, free_chance);
}