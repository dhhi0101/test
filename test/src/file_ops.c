#include "file_ops.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

char file_queue[MAX_FILES][PATH_MAX];
int file_count = 0;

// 스캐너
void scan_directory_recursive(const char *base_path) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path[PATH_MAX];

    if (!(dir = opendir(base_path))) return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // 안전한 경로 생성 (snprintf 사용)
        int written = snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
        
        // 경로가 너무 길어서 잘렸다면 건너뜀
        if (written >= (int)sizeof(path)) continue; 
        
        if (lstat(path, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                scan_directory_recursive(path);
            } 
            else if (S_ISREG(statbuf.st_mode)) {
                if (file_count < MAX_FILES) {
                    // [수정 2] 큐에 넣을 때도 안전하게 복사
                    snprintf(file_queue[file_count], PATH_MAX, "%s", path);
                    file_count++;
                }
            }
        }
    }
    closedir(dir);
}

