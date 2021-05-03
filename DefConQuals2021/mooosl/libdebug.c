#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void * calloc(size_t count, size_t size){
	void * result;
	void * (*original)(size_t, size_t);
	original = dlsym(RTLD_NEXT,"calloc");
	result = (*original)(count, size);
	printf("CALLOC: %#lx, %p\n", count*size, result);
	return result;
}

void free(void * ptr){
        void (*original)(void *);
        printf("FREE: %p\n", ptr);
        original = dlsym(RTLD_NEXT,"free");
        (*original)(ptr);
	return;
}
