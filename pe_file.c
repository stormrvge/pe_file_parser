#include "pe_file.h"

struct pe_file pe_file_init(unsigned char** file_data)
{
	struct pe_file pe;
	
	pe.file_data = *file_data;
	pe.dosHeader = 0;
	pe.imageNTHeaders = 0;
	pe.sectionHeader = 0;
	pe.importSection = 0;
	pe.importDescriptor = 0;
	pe.thunkData = 0;
	pe.thunk = 0;
	pe.rawOffset = 0;

	// IMAGE_DOS_HEADER
	pe.dosHeader = (PIMAGE_DOS_HEADER)pe.file_data;

	// IMAGE_NT_HEADERS
	pe.imageNTHeaders = (PIMAGE_NT_HEADERS)(pe.file_data + pe.dosHeader->e_lfanew);

	return pe;
}

void pe_file_print(struct pe_file* pe_file)
{
	// Adress of entry point
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", pe_file->imageNTHeaders->OptionalHeader.AddressOfEntryPoint);


	// SECTION_HEADERS
	printf("\n******* SECTION HEADERS *******\n");

	// get offset to first section headeer
	unsigned char* sectionLocation = (unsigned char*)pe_file->imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER))
		+ (DWORD)pe_file->imageNTHeaders->FileHeader.SizeOfOptionalHeader;

	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = pe_file->imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;



	// print section data
	for (int i = 0; i < pe_file->imageNTHeaders->FileHeader.NumberOfSections; i++) {
		pe_file->sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", pe_file->sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", pe_file->sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", pe_file->sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", pe_file->sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", pe_file->sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", pe_file->sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", pe_file->sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", pe_file->sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", pe_file->sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", pe_file->sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= pe_file->sectionHeader->VirtualAddress
			&& importDirectoryRVA < pe_file->sectionHeader->VirtualAddress + pe_file->sectionHeader->Misc.VirtualSize)
		{
			pe_file->importSection = pe_file->sectionHeader;
		}


		if ((pe_file->sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
		{
			printf("Code:\n\n");

			const unsigned char* p = (unsigned char*)pe_file->file_data + pe_file->sectionHeader->PointerToRawData;
			const unsigned char* pEnd = p + pe_file->sectionHeader->SizeOfRawData;

			while (p < pEnd)
			{
				printf("%c", (*p++));
			}

			printf("\nEnd Of Section Code\n\n");
		}

		sectionLocation += sectionSize;
	}
}

void pe_file_data_save(struct pe_file* pe_file, char* filename_section, char* filename_binary)
{
	FILE* sec_file;
	FILE* bin_file;

	sec_file = fopen(filename_section, "w");
	bin_file = fopen(filename_binary, "w");

	// Adress of entry point
	fprintf(sec_file, "\t0x%x\t\tAddress Of Entry Point (.text)\n", pe_file->imageNTHeaders->OptionalHeader.AddressOfEntryPoint);


	// SECTION_HEADERS
	fprintf(sec_file, "\n******* SECTION HEADERS *******\n");

	// get offset to first section headeer
	unsigned char* sectionLocation = (unsigned char*)pe_file->imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER))
		+ (DWORD)pe_file->imageNTHeaders->FileHeader.SizeOfOptionalHeader;

	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = pe_file->imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;



	// print section data
	for (int i = 0; i < pe_file->imageNTHeaders->FileHeader.NumberOfSections; i++) {
		pe_file->sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		fprintf(sec_file, "\t%s\n", pe_file->sectionHeader->Name);
		fprintf(sec_file, "\t\t0x%x\t\tVirtual Size\n", pe_file->sectionHeader->Misc.VirtualSize);
		fprintf(sec_file, "\t\t0x%x\t\tVirtual Address\n", pe_file->sectionHeader->VirtualAddress);
		fprintf(sec_file, "\t\t0x%x\t\tSize Of Raw Data\n", pe_file->sectionHeader->SizeOfRawData);
		fprintf(sec_file, "\t\t0x%x\t\tPointer To Raw Data\n", pe_file->sectionHeader->PointerToRawData);
		fprintf(sec_file, "\t\t0x%x\t\tPointer To Relocations\n", pe_file->sectionHeader->PointerToRelocations);
		fprintf(sec_file, "\t\t0x%x\t\tPointer To Line Numbers\n", pe_file->sectionHeader->PointerToLinenumbers);
		fprintf(sec_file, "\t\t0x%x\t\tNumber Of Relocations\n", pe_file->sectionHeader->NumberOfRelocations);
		fprintf(sec_file, "\t\t0x%x\t\tNumber Of Line Numbers\n", pe_file->sectionHeader->NumberOfLinenumbers);
		fprintf(sec_file, "\t\t0x%x\tCharacteristics\n", pe_file->sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= pe_file->sectionHeader->VirtualAddress
			&& importDirectoryRVA < pe_file->sectionHeader->VirtualAddress + pe_file->sectionHeader->Misc.VirtualSize)
		{
			pe_file->importSection = pe_file->sectionHeader;
		}


		if ((pe_file->sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
		{
			const unsigned char* p = (unsigned char*)pe_file->file_data + pe_file->sectionHeader->PointerToRawData;
			const unsigned char* pEnd = p + pe_file->sectionHeader->SizeOfRawData;

			while (p < pEnd)
			{
				fprintf(bin_file, "%c", (*p++));
			}
		}

		sectionLocation += sectionSize;
	}
}