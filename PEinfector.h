#ifndef PEINFECTOR_H
#define PEINFECTOR_H


#include <stdio.h>
#include <stdint.h>

#include "PE.h"


#define P2ALIGNUP(x, align) (-(-(x) & -(align)))




void pe_print_section_header(pe_section_header* header);

int pe_infect_section(pe_dos_header* dos_header, pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size);
int pe64_infect_section(pe_dos_header* dos_header, pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size);

int pe_infect_new_section(pe_dos_header* dos_header, pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name);
int pe64_infect_new_section(pe_dos_header* dos_header, pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name);


#endif
