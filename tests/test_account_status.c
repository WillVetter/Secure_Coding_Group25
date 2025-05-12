#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// Tests account_is_banned, account_is_expired, account_record_login_success, account_record_login_failure are:
// (1) acc must be non-NULL.

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_status tests/test_account_status.c src/account.c -Isrc -lsodium
// ./test_account_status


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
    account_t *account;

    printf("Test 1: Check banned status for a banned account\n");
    account = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    if (!account) {
        printf("FAIL: Account creation failed unexpectedly\n");
        return 1;
    }

    // Banned account
    account->unban_time = time(NULL) + 100; // Unban time is after 100 seconds
    if (account_is_banned(account)) {
        printf("PASS: Account is correctly banned\n");
    } else {
        printf("FAIL: Account is not banned\n");
    }

    // Unbanned account
    account->unban_time = time(NULL) - 60; // Unban time passed 100 seconds ago
    if (!account_is_banned(account)) {
        printf("PASS: Account is correctly not banned\n");
    } else {
        printf("FAIL: Account is incorrectly banned\n");
    }

    printf("\nTest 2: Check expired status for an expired account\n");
    // Expired account
    account->expiration_time = time(NULL) - 100; // Expiration time passed 100 seconds ago
    if (account_is_expired(account)) {
        printf("PASS: Account is correctly expired\n");
    } else {
        printf("FAIL: Account is not expired\n");
    }

    // Simulate a non-expired account
    account->expiration_time = time(NULL) + 100; // Expiration time is after 100 seconds
    if (!account_is_expired(account)) {
        printf("PASS: Account is correctly not expired\n");
    } else {
        printf("FAIL: Account is incorrectly expired\n");
    }

    account_free(account);
    return 0;
}