#ifndef PE_SECTION_PARSER_FILE_READER
#define PE_SECTION_PARSER_FILE_READER

#include <stdio.h>
#include <stdbool.h>
#include <Windows.h>

bool file_open(FILE** file, char* path);
unsigned char* file_read_data(FILE* file, size_t* filesize);
bool file_close(FILE* file);

#endif // !PE_SECTION_PARSER_FILE_READER
