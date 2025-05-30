#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"
#include "db.h"

#include <stdarg.h>
#include "banned.h"

// Tests all arguments in account_set_unban_time, account_set_expiration_time, account_is_banned, account_is_expired are:
// (1) acc must be non-NULL

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_status tests/test_account_status.c src/account.c src/stubs.c -Isrc -lsodium
// ./test_account_status

int main() {
    account_t *account;

    log_message(LOG_INFO, "Test 1: Check banned account is banned\n");
    account = account_create("user", "password", "user@example.com", "2000-01-01");
    if (!account) {
        log_message(LOG_ERROR, "[FAIL] Account creation failed unexpectedly\n");
        return 1;
    }

    // Banned account
    account_set_unban_time(account, time(NULL) + 100); // Unban time is after 100 seconds
    if (account_is_banned(account)) {
        log_message(LOG_INFO, "[PASS] Banned account is banned\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Banned account is not banned\n");
    }

    // Unbanned account
    account_set_unban_time(account, time(NULL) - 100); // Unban time passed 100 seconds ago
    if (!account_is_banned(account)) {
        log_message(LOG_INFO, "[PASS] Account is not banned\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Account is banned\n");
    }

    // Expired account
    log_message(LOG_INFO, "Test 2: Check expired status for an expired account\n");
    account_set_expiration_time(account, time(NULL) - 100); // Expiration time passed 100 seconds ago
    if (account_is_expired(account)) {
        log_message(LOG_INFO, "[PASS] Account is expired\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Account is not expired\n");
    }

    // Not expired account
    account_set_expiration_time(account, time(NULL) + 100); // Expiration time is after 100 seconds
    if (!account_is_expired(account)) {
        log_message(LOG_INFO, "[PASS] Account is not expired\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] Account is expired\n");
    }

    // Test banning NULL account
    log_message(LOG_INFO, "Test 3: Check banned and expired status for NULL account\n");
    if (!account_is_banned(NULL)) {
        log_message(LOG_INFO, "[PASS] account_is_banned rejected NULL account\n");
    } else {
        log_message(LOG_ERROR, "[FAIL] account_is_banned accepted NULL account\n");
    }

    // Test expired status with NULL account
    if (!account_is_expired(NULL)) {
        log_message(LOG_INFO, "[PASS] account_is_expired rejected NULL account");
    } else {
        log_message(LOG_ERROR, "[FAIL] account_is_expired accepted NULL account\n");
    }

    account_free(account);
    return 0;
}