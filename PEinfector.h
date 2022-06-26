#ifndef PEINFECTOR_H
#define PEINFECTOR_H


#include <stdio.h>
#include <stdint.h>

#include "PE.h"




void pe_print_section_header(pe_section_header* header);

int pe_infect_section(FILE* f, FILE* out_f, pe_dos_header* dos_header, pe_nt_header* nt_header, unsigned char* xcode, uint32_t xcode_size);


#endif
