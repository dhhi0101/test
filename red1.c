// red1.c
// SAFE RED-team simulator.
// Usage: ./red1 <target_dir>
// Creates: <absolute_target>_simulated_encrypted/*
// DOES NOT MODIFY ORIGINAL FILES.

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} strvec;

static void vec_init(strvec *v) { v->items = NULL; v->len = 0; v->cap = 0; }
static void vec_push(strvec *v, const char *s) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 256;
        v->items = realloc(v->items, v->cap * sizeof(char*));
    }
    v->items[v->len++] = strdup(s);
}
static void vec_free(strvec *v) {
    for (size_t i=0;i<v->len;i++) free(v->items[i]);
    free(v->items);
    v->items = NULL; v->len = 0; v->cap = 0;
}

static size_t next_index = 0;
static pthread_mutex_t idx_lock = PTHREAD_MUTEX_INITIALIZER;

static char src_root[PATH_MAX];
static char out_root[PATH_MAX];
static strvec files;
static int worker_count = 1;
static size_t max_write_bytes = 8192; // cap per file for simulated payload

// FNV-1a 64-bit (simple fingerprint)
static uint64_t fnv1a_hash_file(const char *path) {
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t h = FNV_OFFSET;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf,1,sizeof(buf),f))>0) {
        for (size_t i=0;i<n;i++) {
            h ^= (uint64_t)buf[i];
            h *= FNV_PRIME;
        }
    }
    fclose(f);
    return h;
}

static int ensure_dir_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    char tmp[PATH_MAX];
    strncpy(tmp, path, PATH_MAX-1); tmp[PATH_MAX-1] = '\0';
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void build_out_path(const char *srcpath, char *outpath, size_t outpath_len) {
    const char *rel = srcpath + strlen(src_root);
    if (*rel == '/') ++rel;
    snprintf(outpath, outpath_len, "%s/%s", out_root, rel);
}

static void process_file(const char *fpath) {
    struct stat st;
    if (stat(fpath, &st) != 0) return;
    if (!S_ISREG(st.st_mode)) return;

    char outpath[PATH_MAX];
    build_out_path(fpath, outpath, sizeof(outpath));

    char outdir[PATH_MAX];
    strncpy(outdir, outpath, sizeof(outdir)-1); outdir[sizeof(outdir)-1]=0;
    char *p = strrchr(outdir, '/');
    if (p) { *p = '\0'; ensure_dir_exists(outdir); }

    uint64_t hash = fnv1a_hash_file(fpath);
    off_t original_size = st.st_size;

    FILE *of = fopen(outpath, "wb");
    if (!of) {
        fprintf(stderr, "생성 실패: %s (errno=%d)\n", outpath, errno);
        return;
    }
    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(of, "=== SIMULATED ENCRYPTION (SAFE) ===\n");
    fprintf(of, "original_path: %s\n", fpath);
    fprintf(of, "original_size: %lld\n", (long long)original_size);
    fprintf(of, "fingerprint_fnv1a: 0x%016llx\n", (unsigned long long)hash);
    fprintf(of, "sim_time: %s\n", timestr);
    fprintf(of, "note: ORIGINAL FILE NOT MODIFIED. FOR TEST PURPOSES ONLY.\n");
    fprintf(of, "====================================\n\n");
    fprintf(of, "[SIMULATED_PAYLOAD_BEGIN]\n");

    size_t to_write = (size_t)(original_size > 0 ? (original_size < (off_t)max_write_bytes ? original_size : max_write_bytes) : 0);
    unsigned char buf[4096];
    memset(buf, 'A' + (hash & 0x0F), sizeof(buf));
    size_t written = 0;
    while (written < to_write) {
        size_t w = to_write - written;
        if (w > sizeof(buf)) w = sizeof(buf);
        fwrite(buf, 1, w, of);
        written += w;
    }
    fprintf(of, "\n[SIMULATED_PAYLOAD_END]\n");
    fclose(of);

    printf("[SIM] %s -> %s (size=%lld)\n", fpath, outpath, (long long)original_size);
}

static void *worker_main(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&idx_lock);
        size_t idx = next_index++;
        pthread_mutex_unlock(&idx_lock);
        if (idx >= files.len) break;
        process_file(files.items[idx]);
    }
    return NULL;
}

static void collect_files_recursive(const char *path) {
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    char child[PATH_MAX];
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name,"..")==0) continue;
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files_recursive(child);
        } else if (S_ISREG(st.st_mode)) {
            vec_push(&files, child);
        } else {
            // ignore symlinks/devices
        }
    }
    closedir(d);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "사용법: %s <target_dir>\n", argv[0]);
        return 1;
    }
    if (!realpath(argv[1], src_root)) {
        perror("realpath 실패");
        return 1;
    }

    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    worker_count = (nprocs > 0) ? (int)nprocs : 1;

    char temp[PATH_MAX];
    strncpy(temp, src_root, sizeof(temp)-1); temp[sizeof(temp)-1]=0;
    size_t len = strlen(temp);
    if (len > 1 && temp[len-1] == '/') temp[len-1] = '\0';
    snprintf(out_root, sizeof(out_root), "%s_simulated_encrypted", temp);

    if (ensure_dir_exists(out_root) != 0) {
        fprintf(stderr, "출력 디렉터리 생성 실패: %s\n", out_root);
        return 1;
    }

    printf("SOURCE: %s\nOUTPUT: %s\nWORKERS: %d\n", src_root, out_root, worker_count);

    vec_init(&files);
    collect_files_recursive(src_root);

    if (files.len == 0) {
        printf("처리할 파일이 없습니다.\n");
        vec_free(&files);
        return 0;
    }

    // randomize to emulate variable processing order
    srand((unsigned)time(NULL));
    for (size_t i = files.len - 1; i > 0; --i) {
        size_t j = rand() % (i+1);
        char *tmp = files.items[i]; files.items[i] = files.items[j]; files.items[j] = tmp;
    }

    pthread_t *threads = malloc(worker_count * sizeof(pthread_t));
    for (int i=0;i<worker_count;i++) pthread_create(&threads[i], NULL, worker_main, NULL);
    for (int i=0;i<worker_count;i++) pthread_join(threads[i], NULL);
    free(threads);

    printf("시뮬레이션 완료. 생성된 결과 확인: %s\n", out_root);

    vec_free(&files);
    return 0;
}
