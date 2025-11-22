#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <limits.h>

#define MAX_FILES 10000

extern char file_queue[MAX_FILES][PATH_MAX];
extern int file_count;

void scan_directory_recursive(const char *base_path);

#endif
