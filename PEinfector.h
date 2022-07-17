#ifndef PEINFECTOR_H
#define PEINFECTOR_H


#include <stdio.h>
#include <stdint.h>

#include "PE.h"


#define P2ALIGNUP(x, align) (-(-(x) & -(align)))


typedef enum arch_mode_ {
	MODE_32BIT = 1,
	MODE_64BIT
} ach_mode;

typedef enum inf_method_ {
	METHOD_CODE_INJECT = 1,
	METHOD_CODE_NEWSECT,
	METHOD_CODE_RESIZE,
} inf_method;




int pe_infect_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, int thread_flag);
int pe64_infect_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size);

int pe_infect_new_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name, int thread_flag);
int pe64_infect_new_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name);

int pe_infect_resize_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, int thread_flag);
int pe64_infect_resize_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size);


#endif
