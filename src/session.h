#ifndef SESSION_H
#define SESSION_H

#include <time.h>
#include <sys/types.h>
#include <pthread.h>
#include <limits.h>

typedef struct {
    char *id;
    char *cwd;
    int shell_fd;
    pid_t shell_pid;
    time_t created_at;
    int hibernated;
} Session;

typedef struct {
    Session **sessions;
    int count;
    int capacity;
    pthread_mutex_t lock;
    int hibernation_mode;
} SessionManager;

SessionManager* session_manager_init(void);
Session* session_create(const char *cwd);
Session* session_get(SessionManager *manager, const char *id);
void session_change_dir(Session *session, const char *new_cwd);
void session_free(Session *session);
void session_manager_free(SessionManager *manager);
int session_manager_add(SessionManager *manager, Session *session);
void session_manager_hibernate(SessionManager *manager);
void session_manager_wake(SessionManager *manager);

#endif
