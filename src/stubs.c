// DO NOT SUBMIT THIS FILE
//
// When submitting your project, this file will be overwritten
// by the automated build and test system.
//
// You can replace these stub implementations with your own code,
// if you wish.

#define CITS3007_PERMISSIVE

#include "logging.h"
#include "db.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "banned.h"

// Persistent bob account
static account_t bob_acc = { 0 };
static bool initialized = false;

/**
 * Abort immediately for unrecoverable errors /
 * invalid program state.
 */
static void panic(const char *msg) {
    fprintf(stderr, "PANIC: %s\n", msg);
    abort();
}

// Logging with thread safety
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(log_level_t level, const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    va_list args;
    va_start(args, fmt);
    switch (level) {
        case LOG_DEBUG: fprintf(stderr, "DEBUG: "); break;
        case LOG_INFO:  fprintf(stderr, "INFO: "); break;
        case LOG_WARN:  fprintf(stderr, "WARNING: "); break;
        case LOG_ERROR: fprintf(stderr, "ERROR: "); break;
        default: panic("Invalid log level"); break;
    }
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    pthread_mutex_unlock(&log_mutex);
}

bool account_lookup_by_userid(const char *userid, account_t *acc) {
    if (!userid || !acc) {
        panic("Invalid arguments to account_lookup_by_userid");
    }

    if (strncmp(userid, "bob", USER_ID_LENGTH) == 0) {
        if (!initialized) {
            strcpy(bob_acc.userid, "bob");
            strcpy(bob_acc.email, "bob.smith@example.com");
            memcpy(bob_acc.birthdate, "1990-01-01", BIRTHDATE_LENGTH);
            // Password is "testpass"
            strcpy(bob_acc.password_hash, "$argon2id$v=19$m=65536,t=2,p=1$8kuYot+vmNgrcCv+lAolhw$5RGvHhmiLLnDQA4Z1FyH6plT07KYvgx4xWLd2AuWTqY");
            initialized = true;
        }

        *acc = bob_acc;
        return true;
    }

    return false;
}

// Getter for the persistent bob account
account_t *get_bob_account_ptr(void) {
    return &bob_acc;
}
