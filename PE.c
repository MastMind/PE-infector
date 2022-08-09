#include <stdlib.h>
#include <stdio.h>

#include "PE.h"


#define WRITE_PE  rewind(out_f); \
					fwrite(dosHeader, sizeof(*dosHeader), 1, out_f); \
					if (dosGap) { \
						fwrite(dosGap, dosGapSize, 1, out_f); \
					} \
					fwrite(ntHeader, sizeof(*ntHeader), 1, out_f); \
					uint64_t zero = 0; \
					fwrite(&zero, 1, ntHeader->nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t) - sizeof(*ntHeader), out_f); \
					list_pe_section_t curSect = sections; \
					while (curSect) { \
						fwrite(&curSect->header, sizeof(pe_section_header), 1, out_f); \
						curSect = curSect->next; \
					} \
					if (sectGap) { \
						fwrite(sectGap, sectGapSize, 1, out_f); \
					} \
					curSect = sections; \
					while (curSect) { \
						fwrite(curSect->data, curSect->header.SizeOfRawData, 1, out_f); \
						curSect = curSect->next; \
					}




static list_pe_section_t build_list_sections(FILE* f, uint16_t sections_table_offset, uint16_t number_of_sections);

void pe_print_section_header(pe_section_header* header) {
	fprintf(stdout, "Section name: %s\n", header->name);
	fprintf(stdout, "Section VirtualSize: 0x%08X\n", header->Misc.VirtualSize);
	fprintf(stdout, "Section VirtualAddress: 0x%08X\n", header->VirtualAddress);
	fprintf(stdout, "Section SizeOfRawData: %u\n", header->SizeOfRawData);
	fprintf(stdout, "Section PointerToRawData: 0x%08X\n", header->PointerToRawData);
	fprintf(stdout, "Section PointerToRelocations: 0x%08X\n", header->PointerToRelocations);
	fprintf(stdout, "Section PointerToLinenumbers: 0x%08X\n", header->PointerToLinenumbers);
	fprintf(stdout, "Section NumberOfRelocations: %u\n", header->NumberOfRelocations);
	fprintf(stdout, "Section NumberOfLinenumbers: %u\n", header->NumberOfLinenumbers);
	fprintf(stdout, "Section Characteristics: 0x%08X\n", header->Characteristics);
}

int pe_parse(FILE* f, pe_dos_header* dosHeader, pe_nt_header* ntHeader, pe64_nt_header* ntHeader64) {
	if (!f || !dosHeader || !ntHeader || !ntHeader64) {
		return -1;
	}
	
	if (fread(dosHeader, sizeof(pe_dos_header), 1, f) == 0) {
		return -2;
	}
	
	if (dosHeader->e_magic != DOS_MAGIC_VALUE) {
		//Missing MZ signature. Bad file
		return -3;
	}
	
	if (fseek(f, dosHeader->e_lfanew, SEEK_SET) < 0) {
		return -4;
	}
	
	if (fread(ntHeader, sizeof(pe_nt_header), 1, f) == 0) {
		return -5;
	}
	
	if (ntHeader->nt_magic != NT_MAGIC_VALUE) {
		//Missing PE signature. Bad file
		return -6;
	}
	
	if (ntHeader->nt_optional_header.magic == IMAGE_NT_OPTIONAL_64_MAGIC) {
		//it is 64bit binary
		//reparse to another header
		fseek(f, dosHeader->e_lfanew, SEEK_SET);
		
		if (fread(ntHeader64, sizeof(pe64_nt_header), 1, f) == 0) {
			return -7;
		}
	} else {
		if (ntHeader->nt_optional_header.image_base < 0x400000 || 
			ntHeader->nt_optional_header.image_base > 0x1000000) {
			if (!(ntHeader->nt_file_header.characteristics & IMAGE_FILE_DLL)) {
				//strange PE file
				return -8;
			}
		}
	}
	
	return 0;
}

list_pe_section_t pe_parse_sections(FILE* f, pe_dos_header* dosHeader, pe_nt_header* ntHeader) {
	if (!f || !dosHeader || !ntHeader) {
		return NULL;
	}
	
	uint16_t sections_table_offset = dosHeader->e_lfanew + ntHeader->nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t);
	
	return build_list_sections(f, sections_table_offset, ntHeader->nt_file_header.number_of_sections);
}

list_pe_section_t pe64_parse_sections(FILE* f, pe_dos_header* dosHeader, pe64_nt_header* ntHeader) {
	if (!f || !dosHeader || !ntHeader) {
		return NULL;
	}
	
	uint16_t sections_table_offset = dosHeader->e_lfanew + ntHeader->nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t);
	
	return build_list_sections(f, sections_table_offset, ntHeader->nt_file_header.number_of_sections);
}

int pe_write(FILE* out_f, pe_dos_header* dosHeader, pe_nt_header* ntHeader, list_pe_section_t sections, char* dosGap, uint16_t dosGapSize, char* sectGap, uint16_t sectGapSize) {
	if (!out_f || !dosHeader || !ntHeader || !sections) {
		return -1;
	}
	
	WRITE_PE
	
	return 0;
}

int pe64_write(FILE* out_f, pe_dos_header* dosHeader, pe64_nt_header* ntHeader, list_pe_section_t sections, char* dosGap, uint16_t dosGapSize, char* sectGap, uint16_t sectGapSize) {
	if (!out_f || !dosHeader || !ntHeader || !sections) {
		return -1;
	}
	
	WRITE_PE
	
	return 0;
}

static list_pe_section_t build_list_sections(FILE* f, uint16_t sections_table_offset, uint16_t number_of_sections) {
	//parse table of section
	list_pe_section_t ret = NULL;
	list_pe_section_t curSect = ret;
	
	for (uint16_t i = 0; i < number_of_sections; i++) {
		fseek(f, sections_table_offset + i * sizeof(pe_section_header), SEEK_SET);
		
		//pe_section_header sectionHeader;
		list_pe_section_t newSect = (list_pe_section_t)malloc(sizeof(list_pe_section));
		if (!newSect) {
			//can't allocate memory for list
			return NULL;
		}
					
		if (fread(&newSect->header, sizeof(pe_section_header), 1, f) == 0) {
			free(newSect);
			return NULL;
		}
		
		//fill section data
		newSect->data = (char*)malloc(newSect->header.SizeOfRawData);
			
		if (!newSect->data) {
			//internal error. Can't alloc memory for store section
			return NULL;
		}
		
		fseek(f, newSect->header.PointerToRawData, SEEK_SET);
		fread(newSect->data, newSect->header.SizeOfRawData, 1, f);
		newSect->next = NULL;
		
		if (!curSect) {
			ret = newSect;
		} else {
			curSect->next = newSect;
		}
		
		curSect = newSect;
	}
	
	return ret;
}
