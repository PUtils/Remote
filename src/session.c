#include "session.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>

static void generate_session_id(char *id, int len) {
    static unsigned long counter = 0;
    time_t now = time(NULL);
    pid_t pid = getpid();

    snprintf(id, len, "sess_%lx_%d_%lu", (unsigned long)now, pid, counter++);
}

Session* session_create(const char *cwd) {
    Session *session = malloc(sizeof(Session));
    if (!session) return NULL;

    session->id = malloc(64);
    if (!session->id) {
        free(session);
        return NULL;
    }
    generate_session_id(session->id, 64);

    session->cwd = malloc(PATH_MAX);
    if (!session->cwd) {
        free(session->id);
        free(session);
        return NULL;
    }
    strncpy(session->cwd, cwd, PATH_MAX - 1);
    session->cwd[PATH_MAX - 1] = '\0';

    session->shell_fd = -1;
    session->shell_pid = -1;
    session->created_at = time(NULL);
    session->hibernated = 0;

    return session;
}

SessionManager* session_manager_init(void) {
    SessionManager *manager = malloc(sizeof(SessionManager));
    if (!manager) return NULL;

    manager->capacity = 10;
    manager->count = 0;
    manager->hibernation_mode = 0;
    manager->sessions = malloc(sizeof(Session*) * manager->capacity);

    if (!manager->sessions) {
        free(manager);
        return NULL;
    }

    pthread_mutex_init(&manager->lock, NULL);
    return manager;
}

int session_manager_add(SessionManager *manager, Session *session) {
    pthread_mutex_lock(&manager->lock);

    if (manager->count >= manager->capacity) {
        manager->capacity *= 2;
        Session **new_sessions = realloc(manager->sessions, sizeof(Session*) * manager->capacity);
        if (!new_sessions) {
            pthread_mutex_unlock(&manager->lock);
            return -1;
        }
        manager->sessions = new_sessions;
    }

    manager->sessions[manager->count++] = session;
    pthread_mutex_unlock(&manager->lock);
    return 0;
}

Session* session_get(SessionManager *manager, const char *id) {
    pthread_mutex_lock(&manager->lock);

    for (int i = 0; i < manager->count; i++) {
        if (strcmp(manager->sessions[i]->id, id) == 0) {
            Session *session = manager->sessions[i];
            pthread_mutex_unlock(&manager->lock);
            return session;
        }
    }

    pthread_mutex_unlock(&manager->lock);
    return NULL;
}

void session_change_dir(Session *session, const char *new_cwd) {
    strncpy(session->cwd, new_cwd, PATH_MAX - 1);
    session->cwd[PATH_MAX - 1] = '\0';
}

void session_manager_hibernate(SessionManager *manager) {
    pthread_mutex_lock(&manager->lock);
    manager->hibernation_mode = 1;

    for (int i = 0; i < manager->count; i++) {
        Session *session = manager->sessions[i];
        if (session->shell_pid > 0) {
            kill(session->shell_pid, SIGTERM);
        }
        session->hibernated = 1;
    }

    pthread_mutex_unlock(&manager->lock);
}

void session_manager_wake(SessionManager *manager) {
    pthread_mutex_lock(&manager->lock);
    manager->hibernation_mode = 0;

    for (int i = 0; i < manager->count; i++) {
        manager->sessions[i]->hibernated = 0;
    }

    pthread_mutex_unlock(&manager->lock);
}

void session_free(Session *session) {
    if (session) {
        if (session->shell_pid > 0) {
            kill(session->shell_pid, SIGTERM);
        }
        if (session->shell_fd >= 0) {
            close(session->shell_fd);
        }
        free(session->id);
        free(session->cwd);
        free(session);
    }
}

void session_manager_free(SessionManager *manager) {
    if (manager) {
        pthread_mutex_lock(&manager->lock);
        for (int i = 0; i < manager->count; i++) {
            session_free(manager->sessions[i]);
        }
        pthread_mutex_unlock(&manager->lock);
        pthread_mutex_destroy(&manager->lock);
        free(manager->sessions);
        free(manager);
    }
}
