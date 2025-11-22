#ifndef SEM_MONITOR_H
#define SEM_MONITOR_H

#include <pthread.h>
#include <sys/types.h>

#define SEM_MONITOR_MAX_OWNERS 128

typedef struct {
    pthread_mutex_t lock;      // 프로세스 공유 뮤텍스
    int max_permits;           // 할당 가능한 최대 허가 수
    int used;                  // 현재 사용 중인 허가 수
    pid_t owners[SEM_MONITOR_MAX_OWNERS]; // 각 슬롯의 소유자 PID (0 == 빈 슬롯)
} sem_monitor_t;

// 초기화: mmap으로 할당된 메모리를 전달
int semmon_init(sem_monitor_t *m, int max_permits);

// 현재 사용 중인 허가 수 조회
int semmon_get_used(sem_monitor_t *m);

// 최대 허가 수 조회
int semmon_get_max_permits(sem_monitor_t *m);

// 호출한 프로세스가 허가 획득 (블로킹)
int semmon_acquire(sem_monitor_t *m);

// 호출한 프로세스가 보유한 허가 반납
int semmon_release(sem_monitor_t *m);

// 특정 PID에 대해 강제 반납 (모니터가 사용)
int semmon_release_pid(sem_monitor_t *m, pid_t pid);

// 모니터 프로세스 시작: 죽은 PID의 슬롯을 주기적으로 회수
// 반환값: 모니터 프로세스 PID (>0) 또는 -1 실패
pid_t semmon_start_monitor(sem_monitor_t *m, unsigned int interval_sec);

// 모니터 프로세스 중지 (SIGTERM 전송)
int semmon_stop_monitor(pid_t mon_pid);

#endif
