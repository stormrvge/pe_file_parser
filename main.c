#include <stdio.h>
#include <Windows.h>

#include "file_reader.h"
#include "pe_file.h"


int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		printf("./pe_file_parser {PATH TO PE FILE} {PATH TO SAVE SECTION INFO} {PATH TO SAVE BIN DATA}\n");
		exit(-1);
	}

	FILE* file;
	size_t file_size = 0;

	file_open(&file, argv[1]);

	unsigned char* file_data = file_read_data(file, &file_size);
	struct pe_file pe_file = pe_file_init(&file_data);

	pe_file_print(&pe_file);
	pe_file_data_save(&pe_file, argv[2], argv[3]);

	file_close(file);
	return 0;
}