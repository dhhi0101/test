#include "sem_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

// 내부 헬퍼: mutex 초기화 (프로세스 공유, robust 가능하면 사용)
static int init_process_mutex(pthread_mutex_t *m) {
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) return -1;
    if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }
#ifdef PTHREAD_MUTEX_ROBUST
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
#endif
    if (pthread_mutex_init(m, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }
    pthread_mutexattr_destroy(&attr);
    return 0;
}

int semmon_init(sem_monitor_t *m, int max_permits) {
    if (!m) return -1;
    if (max_permits <= 0 || max_permits > SEM_MONITOR_MAX_OWNERS) return -1;
    memset(m, 0, sizeof(*m));
    if (init_process_mutex(&m->lock) != 0) return -1;
    m->max_permits = max_permits;
    m->used = 0;
    for (int i = 0; i < SEM_MONITOR_MAX_OWNERS; i++) m->owners[i] = 0;
    return 0;
}

int semmon_get_used(sem_monitor_t *m) {
    if (!m) return -1;
    int used;
    if (pthread_mutex_lock(&m->lock) == 0) {
        used = m->used;
        pthread_mutex_unlock(&m->lock);
    } else {
        // 실패 시 보수적으로 큰 값 반환
        used = m->max_permits;
    }
    return used;
}

int semmon_get_max_permits(sem_monitor_t *m) {
    if (!m) return 0;
    return m->max_permits;
}

int semmon_acquire(sem_monitor_t *m) {
    if (!m) return -1;
    pid_t self = getpid();
    while (1) {
        if (pthread_mutex_lock(&m->lock) != 0) {
            // mutex 회복 불가하면 짧게 대기
            usleep(10000);
            continue;
        }

        if (m->used < m->max_permits) {
            // 빈 슬롯 찾아서 등록
            for (int i = 0; i < m->max_permits; i++) {
                if (m->owners[i] == 0) {
                    m->owners[i] = self;
                    m->used++;
                    pthread_mutex_unlock(&m->lock);
                    return 0;
                }
            }
            // 드물게 일어날 수 있는 불일치 처리
            pthread_mutex_unlock(&m->lock);
            usleep(10000);
            continue;
        }
        pthread_mutex_unlock(&m->lock);
        usleep(10000);
    }
    // unreachable
    return -1;
}

int semmon_release(sem_monitor_t *m) {
    if (!m) return -1;
    pid_t self = getpid();
    int released = 0;
    if (pthread_mutex_lock(&m->lock) != 0) return -1;
    for (int i = 0; i < m->max_permits; i++) {
        if (m->owners[i] == self) {
            m->owners[i] = 0;
            m->used--;
            released++;
        }
    }
    pthread_mutex_unlock(&m->lock);
    return released;
}

int semmon_release_pid(sem_monitor_t *m, pid_t pid) {
    if (!m) return -1;
    int released = 0;
    if (pthread_mutex_lock(&m->lock) != 0) return -1;
    for (int i = 0; i < m->max_permits; i++) {
        if (m->owners[i] == pid) {
            m->owners[i] = 0;
            m->used--;
            released++;
        }
    }
    pthread_mutex_unlock(&m->lock);
    return released;
}

// 모니터 루프: 죽은 PID를 찾아 회수
static void monitor_loop(sem_monitor_t *m, unsigned int interval_sec) {
    if (!m) return;
    while (1) {
        // 부모가 이미 종료되어도 계속 돌 수 있으므로 모니터는 SIGTERM으로 종료시킴
        if (pthread_mutex_lock(&m->lock) == 0) {
            for (int i = 0; i < m->max_permits; i++) {
                pid_t p = m->owners[i];
                if (p == 0) continue;
                // kill(pid,0)으로 프로세스 존재 확인
                if (kill(p, 0) == -1) {
                    if (errno == ESRCH) {
                        // 프로세스 없음 -> 회수
                        m->owners[i] = 0;
                        if (m->used > 0) m->used--;
                    }
                }
            }
            pthread_mutex_unlock(&m->lock);
        }
        sleep(interval_sec);
    }
}

pid_t semmon_start_monitor(sem_monitor_t *m, unsigned int interval_sec) {
    if (!m) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // child: monitor
        // 설치된 시그널의 기본 동작을 유지하고, 무한 루프 실행
        monitor_loop(m, (interval_sec == 0) ? 1 : interval_sec);
        _exit(0);
    }
    // parent: 반환
    return pid;
}

int semmon_stop_monitor(pid_t mon_pid) {
    if (mon_pid <= 0) return -1;
    if (kill(mon_pid, SIGTERM) == -1) return -1;
    return 0;
}
