/*
* Colored-Cap modifications: 
*      Author: Ruben Sturm
*      Copyright (c) 2025 Ericsson AB 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((optnone))
int main(){
    for(int i=0;i<8100000;i++){
        void* p = malloc(8);
        if(rand()%1000<=998){
            free(p);
        }
    }
}
