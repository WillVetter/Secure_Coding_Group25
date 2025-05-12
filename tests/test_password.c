#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// gcc -o test_password tests/test_password.c src/account.c -Isrc -lsodium

void log_message(log_level_t level, const char *fmt, ...) {
    const char *level_str;
    switch (level) {
        case LOG_DEBUG:
            level_str = "DEBUG";
            break;
        case LOG_INFO:
            level_str = "INFO";
            break;
        case LOG_WARN:
            level_str = "WARN";
            break;
        case LOG_ERROR:
            level_str = "ERROR";
            break;
        default:
            level_str = "UNKNOWN";
            break;
    }

    printf("[%s] ", level_str);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

int main() {
    printf("Test 1: Validate password with NULL\n");
    account_t *account = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    if (account_validate_password(account, NULL)) {
        printf("Password validation succeeded unexpectedly!\n");
    } else {
        printf("Password validation failed as expected!\n");
    }

    printf("Test 2: Update password with NULL\n");
    if (account_update_password(account, NULL)) {
        printf("Password update succeeded unexpectedly!\n");
    } else {
        printf("Password update failed as expected!\n");
    }

    account_free(account);
    return 0;
}