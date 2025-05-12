#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// gcc -o test_account_creation tests/test_account_creation.c src/account.c -Isrc -lsodium

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
    printf("Test 1: Create account with invalid email\n");
    account_t *account = account_create("testuser", "password123", "invalid-email", "1990-01-01");
    if (account) {
        printf("Account creation succeeded unexpectedly!\n");
        account_free(account);
    } else {
        printf("Account creation failed as expected!\n");
    }

    printf("Test 2: Create account with invalid birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "01-01-1990");
    if (account) {
        printf("Account creation succeeded unexpectedly!\n");
        account_free(account);
    } else {
        printf("Account creation failed as expected!\n");
    }

    printf("Test 2: Create account with wrong date\n");
    account = account_create("testuser", "password123", "test@example.com", "1800-01-01");
    if (account) {
        printf("Account creation succeeded unexpectedly!\n");
        account_free(account);
    } else {
        printf("Account creation failed as expected!\n");
    }


    return 0;
}
