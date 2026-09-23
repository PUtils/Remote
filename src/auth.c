#include "auth.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>

static void sha256_hash(const char *input, const char *salt, char *output) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;

    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, (unsigned char *)salt, strlen(salt));
    CC_SHA256_Update(&ctx, (unsigned char *)input, strlen(input));
    CC_SHA256_Final(hash, &ctx);

    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[CC_SHA256_DIGEST_LENGTH * 2] = '\0';
}

AuthContext* auth_init(const char *password, int max_attempts, int lockout_duration) {
    AuthContext *ctx = malloc(sizeof(AuthContext));
    if (!ctx) return NULL;

    ctx->password_hash = malloc(256);
    if (!ctx->password_hash) {
        free(ctx);
        return NULL;
    }

    char salt[32];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 31; i++) {
        salt[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 62];
    }
    salt[31] = '\0';

    char temp[256];
    sha256_hash(password, salt, temp);

    snprintf(ctx->password_hash, 256, "$sha256$%s$%s", salt, temp);

    ctx->failed_attempts = 0;
    ctx->lockout_until = 0;
    ctx->max_attempts = max_attempts;
    ctx->lockout_duration = lockout_duration;

    return ctx;
}

int auth_verify(AuthContext *ctx, const char *password) {
    time_t now = time(NULL);

    if (ctx->lockout_until > now) {
        return 0;
    }

    char *salt_ptr = strchr(ctx->password_hash, '$') + 1;
    salt_ptr = strchr(salt_ptr, '$') + 1;
    char *salt_end = strchr(salt_ptr, '$');

    if (!salt_end) {
        ctx->failed_attempts++;
        if (ctx->failed_attempts >= ctx->max_attempts) {
            ctx->lockout_until = now + ctx->lockout_duration;
        }
        return 0;
    }

    char salt[32];
    int salt_len = salt_end - salt_ptr;
    strncpy(salt, salt_ptr, salt_len);
    salt[salt_len] = '\0';

    char computed_hash[256];
    sha256_hash(password, salt, computed_hash);

    char expected[256];
    snprintf(expected, 256, "$sha256$%s$%s", salt, computed_hash);

    if (strcmp(expected, ctx->password_hash) == 0) {
        ctx->failed_attempts = 0;
        ctx->lockout_until = 0;
        return 1;
    }

    ctx->failed_attempts++;
    if (ctx->failed_attempts >= ctx->max_attempts) {
        ctx->lockout_until = now + ctx->lockout_duration;
    }

    return 0;
}

void auth_reset_attempts(AuthContext *ctx) {
    ctx->failed_attempts = 0;
    ctx->lockout_until = 0;
}

void auth_free(AuthContext *ctx) {
    if (ctx) {
        free(ctx->password_hash);
        free(ctx);
    }
}
