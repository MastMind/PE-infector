#ifndef PE_H
#define PE_H


#include <stdint.h>




#define SECTION_SHORT_NAME_LENGTH 8
#define SECTION_CHARACTER_EXECUTABLE 0x00000020
#define DLL_CHARACTER_CAN_MOVE       0x0040
#define DLL_CHARACTER_NX_COMPAT      0x0100
#define IMAGE_RELOCS_STRIPPED        0x0001

#define IMAGE_NT_OPTIONAL_32_MAGIC   0x10b
#define IMAGE_NT_OPTIONAL_64_MAGIC   0x20b


typedef enum arch_mode_ {
	MODE_32BIT = 1,
	MODE_64BIT
} ach_mode;

typedef struct pe_dos_header_ {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res;
	uint16_t reserved0[3];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2;
	uint16_t reserved1[9];
	uint16_t e_lfanew;
} __attribute__((packed)) pe_dos_header;

typedef struct pe_file_header_ {
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_date_stamp;
	uint32_t pointer_to_symbol_table;
	uint32_t number_of_symbols;
	uint16_t size_of_optional_header;
	uint16_t characteristics;
} __attribute__((packed)) pe_file_header;

typedef struct pe_data_directories_ {
	uint32_t export_directory_rva;
	uint32_t export_directory_size;
	uint32_t import_directory_rva;
	uint32_t import_directory_size;
	uint32_t resource_directory_rva;
	uint32_t resource_directory_size;
	uint32_t exception_directory_rva;
	uint32_t exception_directory_size;
	uint32_t security_directory_rva;
	uint32_t security_directory_size;
	uint32_t relocation_directory_rva;
	uint32_t relocation_directory_size;
	uint32_t debug_directory_rva;
	uint32_t debug_directory_size;
	uint32_t architecture_directory_rva;
	uint32_t architecture_directory_size;
	uint32_t reserved0[2];
	uint32_t tls_directory_rva;
	uint32_t tls_directory_size;
	uint32_t configuration_directory_rva;
	uint32_t configuration_directory_size;
	uint32_t bound_import_directory_rva;
	uint32_t bound_import_directory_size;
	uint32_t import_address_table_directory_rva;
	uint32_t import_address_table_directory_size;
	uint32_t delay_import_directory_rva;
	uint32_t delay_import_directory_size;
	uint32_t dot_net_metadata_directory_rva;
	uint32_t dot_net_metadata_directory_size;
} __attribute__((packed)) pe_data_directories;

typedef struct pe_optional_header_ {
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint32_t base_of_data;
	uint32_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t checksum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint32_t size_of_stack_reserve;
	uint32_t size_of_stack_commit;
	uint32_t size_of_heap_reserve;
	uint32_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	pe_data_directories data_directories;
} __attribute__((packed)) pe_optional_header;

typedef struct pe64_optional_header_ {
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint64_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t checksum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint64_t size_of_stack_reserve;
	uint64_t size_of_stack_commit;
	uint64_t size_of_heap_reserve;
	uint64_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	pe_data_directories data_directories;
} __attribute__((packed)) pe64_optional_header;

typedef struct pe_nt_header_ {
	uint32_t nt_magic;
	pe_file_header nt_file_header;
	pe_optional_header nt_optional_header;
} __attribute__((packed)) pe_nt_header;

typedef struct pe64_nt_header_ {
	uint32_t nt_magic;
	pe_file_header nt_file_header;
	pe64_optional_header nt_optional_header;
} __attribute__((packed)) pe64_nt_header;

typedef struct pe_section_header_ {
	char name[SECTION_SHORT_NAME_LENGTH];
    union {
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} __attribute__((packed)) pe_section_header;


#endif
