#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// Tests all arguments in account_validate_password, account_update_password are:
// 1) acc and new_plaintext_password must be non-NULL.
// 2) new_plaintext_password must be a valid, null-terminated string.

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_passwords tests/test_passwords.c src/account.c -Isrc -lsodium
// ./test_passwords

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
    account_t *account = account_create("testuser", "password123", "test@example.com", "1990-01-01");
     
    printf("\nTest 1: Validate password with NULL account\n");
    if (account_validate_password(NULL, "password123")) {
        printf("FAIL: Password validation succeeded unexpectedly with NULL account!\n");
    } else {
        printf("PASS: Password validation failed as expected with NULL account!\n");
    }

    
    printf("\nTest 2: Update password with NULL account\n");
    if (account_update_password(NULL, "newpassword123")) {
        printf("FAIL: Password update succeeded unexpectedly with NULL account!\n");
    } else {
        printf("PASS: Password update failed as expected with NULL account!\n");
    }

    printf("\nTest 3: Validate password with NULL\n");
    if (account_validate_password(account, NULL)) {
        printf("FAIL: Password validation succeeded unexpectedly!\n");
    } else {
        printf("PASS: Password validation failed as expected!\n");
    }

      printf("\nTest 4: Update password with NULL\n");
    if (account_update_password(account, NULL)) {
        printf("FAIL: Password update succeeded unexpectedly!\n");
    } else {
        printf("PASS: Password update failed as expected!\n");
    }

    printf("\nTest 5: Validate correct password\n");
    if (account_validate_password(account, "password123")) {
        printf("PASS: Password validation succeeded as expected!\n");
    } else {
        printf("FAIL: Password validation failed unexpectedly!\n");
    }

    printf("\nTest 6: Validate incorrect password\n");
    if (account_validate_password(account, "wrongpassword")) {
        printf("FAIL: Password validation succeeded unexpectedly!\n");
    } else {
        printf("PASS: Password validation failed as expected!\n");
    }

    printf("\nTest 7: Update password to a new valid password\n");
    if (account_update_password(account, "newpassword123")) {
        printf("PASS: Password update succeeded as expected!\n");
    } else {
        printf("FAIL: Password update failed unexpectedly!\n");
    }

    printf("\nTest 8: Validate new password\n");
    if (account_validate_password(account, "newpassword123")) {
        printf("PASS: Password validation succeeded as expected with new password!\n");
    } else {
        printf("FAIL: Password validation failed unexpectedly with new password!\n");
    }

    printf("\nTest 9: Validate old password after update\n");
    if (account_validate_password(account, "password123")) {
        printf("FAIL: Password validation succeeded unexpectedly with old password!\n");
    } else {
        printf("PASS: Password validation failed as expected with old password!\n");
    }

    account_free(account);

    return 0;
}