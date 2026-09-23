#ifndef AUTH_H
#define AUTH_H

#include <time.h>

typedef struct {
    char *password_hash;
    int failed_attempts;
    time_t lockout_until;
    int max_attempts;
    int lockout_duration;
} AuthContext;

AuthContext* auth_init(const char *password, int max_attempts, int lockout_duration);
int auth_verify(AuthContext *ctx, const char *password);
void auth_reset_attempts(AuthContext *ctx);
void auth_free(AuthContext *ctx);

#endif
