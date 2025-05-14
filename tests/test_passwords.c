#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"
#include "db.h"
#include "banned.h"

// Tests all arguments in account_validate_password, account_update_password are:
// 1) acc and new_plaintext_password must be non-NULL.
// 2) new_plaintext_password must be a valid, null-terminated string.

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_passwords tests/test_passwords.c src/account.c src/stubs.c -Isrc -lsodium
// ./test_passwords

int main() {
    account_t *account = account_create("user", "password", "user@example.com", "2000-01-01");
     
    log_message(LOG_INFO, "Test 1: Validate password with NULL account\n");
    if (account_validate_password(NULL, "password")) {
        log_message(LOG_ERROR, "[FAIL] Password validation succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password validation failed\n");
    }

    log_message(LOG_INFO, "Test 2: Validate password with NULL password\n");
    if (account_validate_password(account, NULL)) {
        log_message(LOG_ERROR, "[FAIL] Password validation succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password validation failed\n");
    }
    
    log_message(LOG_INFO, "Test 3: Update password with NULL account\n");
    if (account_update_password(NULL, "newpassword")) {
        log_message(LOG_ERROR, "[FAIL] Password update succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password update failed\n");
    }

      log_message(LOG_INFO, "Test 4: Update password with NULL password\n");
    if (account_update_password(account, NULL)) {
        log_message(LOG_ERROR, "[FAIL] Password update succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password update failed\n");
    }

    log_message(LOG_INFO, "Test 5: Validate correct password\n");
    if (account_validate_password(account, "password")) {
        log_message(LOG_INFO, "[PASS] Password validation succeeded\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Password validation failed\n");
    }

    log_message(LOG_INFO, "Test 6: Validate incorrect password\n");
    if (account_validate_password(account, "wrongpassword")) {
        log_message(LOG_ERROR, "[FAIL] Password validation succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password validation failed\n");
    }

    // Update and validate new password
    log_message(LOG_INFO, "Test 7: Update password to a new valid password\n");
    if (account_update_password(account, "newpassword")) {
        log_message(LOG_INFO, "[PASS] Password update succeeded\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Password update failed\n");
    }

    log_message(LOG_INFO, "Test 8: Validate new password\n");
    if (account_validate_password(account, "newpassword")) {
        log_message(LOG_INFO, "[PASS] Password validation succeeded\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Password validation failed\n");
    }

    // Test old password doesn't work anymore
    log_message(LOG_INFO, "Test 9: Validate old password after update\n");
    if (account_validate_password(account, "password")) {
        log_message(LOG_ERROR, "[FAIL] Password validation succeeded\n");
    } else {
        log_message(LOG_INFO, "[PASS] Password validation failed\n");
    }

    account_free(account);

    return 0;
}