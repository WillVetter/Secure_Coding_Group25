#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"
#include "db.h"

#include <stdarg.h>

// Tests all arguments in account_set_unban_time, account_set_expiration_time, account_is_banned, account_is_expired are:
// (1) acc must be non-NULL

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_status tests/test_account_status.c src/account.c src/stubs.c -Isrc -lsodium
// ./test_account_status

int main() {
    account_t *account;

    printf("Test 1: Check banned status for a banned account\n");
    account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    if (!account) {
        printf("FAIL: Account creation failed unexpectedly\n");
        return 1;
    }

    // Banned account
    account_set_unban_time(account, time(NULL) + 100); // Unban time is after 100 seconds
    if (account_is_banned(account)) {
        printf("PASS: Account is correctly banned\n");
    } else {
        printf("FAIL: Account is not banned\n");
    }

    // Unbanned account
    account_set_unban_time(account, time(NULL) - 100); // Unban time passed 100 seconds ago
    if (!account_is_banned(account)) {
        printf("PASS: Account is correctly not banned\n");
    } else {
        printf("FAIL: Account is incorrectly banned\n");
    }

    printf("\nTest 2: Check expired status for an expired account\n");
    // Expired account
    account_set_expiration_time(account, time(NULL) - 100); // Expiration time passed 100 seconds ago
    if (account_is_expired(account)) {
        printf("PASS: Account is correctly expired\n");
    } else {
        printf("FAIL: Account is not expired\n");
    }

    // Non-expired account
    account_set_expiration_time(account, time(NULL) + 100); // Expiration time is after 100 seconds
    if (!account_is_expired(account)) {
        printf("PASS: Account is correctly not expired\n");
    } else {
        printf("FAIL: Account is incorrectly expired\n");
    }

    printf("\nTest 3: Check banned and expired status for NULL account\n");
    // Test banned status with NULL account
    if (!account_is_banned(NULL)) {
        printf("PASS: account_is_banned correctly handled NULL account\n");
    } else {
        printf("FAIL: account_is_banned did not handle NULL account correctly\n");
    }

    // Test expired status with NULL account
    if (!account_is_expired(NULL)) {
        printf("PASS: account_is_expired correctly handled NULL account\n");
    } else {
        printf("FAIL: account_is_expired did not handle NULL account correctly\n");
    }

    account_free(account);
    return 0;
}