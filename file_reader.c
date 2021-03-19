#include "file_reader.h"

#define READ_MODE "rb"

bool file_open(FILE** file, char* path)
{
	if (*file == NULL)
	{
		printf("FILE corrupted\n");
		return false;
	}
	if (path == NULL)
	{
		printf("Invalid path to file\n");
		return false;
	}
	
	*file = fopen(path, READ_MODE);
	if (*file == NULL)
	{
		printf("File does not exits or user does not have permission\n");
		return false;
	}

	return true;
}


unsigned char* file_read_data(FILE* file, size_t* file_size)
{
	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	unsigned char* data = malloc(sizeof(unsigned char*) * (*file_size));
	fread(data, 1, (*file_size), file);

	return data;
}


bool file_close(FILE* file)
{
	if (file == NULL)
	{
		printf("FILE corrupted\n");
		return false;
	}
	if (fclose(file) != 0)
	{
		printf("File was not closed\n");
		return false;
	}

	return true;
}