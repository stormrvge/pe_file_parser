#ifndef PE_SECTION_PARSER_PE_FILE
#define PE_SECTION_PARSER_PE_FILE

#include <Windows.h>
#include <stdio.h>

struct pe_file
{
	unsigned char* file_data;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS imageNTHeaders;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_SECTION_HEADER importSection;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
	PIMAGE_THUNK_DATA thunkData;
	DWORD thunk;
	DWORD rawOffset;
};

struct pe_file pe_file_init(unsigned char** file_data);
void pe_file_print(struct pe_file* pe_file);
void pe_file_data_save(struct pe_file* pe_file, char* filename_section, char* filename_binary);

#endif // !PE_SECTION_PARSER_PE_FILE
