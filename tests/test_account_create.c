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

// Tests all arguments in account_create() are:
// (1) All arguments must be valid, null-terminated strings. 
// (2) None of the pointers may be NULL.
// (3) Birthdate is in format YYYY-MM-DD

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_create tests/test_account_create.c src/account.c src/stubs.c -Isrc -lsodium
// ./test_account_create

int main() {
    account_t *account;

    log_message(LOG_INFO, "\nTest 1: Create account with NULL username\n");
    account = account_create(NULL, "password", "user@example.com", "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 2: Create account with NULL password\n");
    account = account_create("user", NULL, "user@example.com", "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 3: Create account with NULL email\n");
    account = account_create("user", "password", NULL, "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 4: Create account with NULL birthdate\n");
    account = account_create("user", "password", "user@example.com", NULL);
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 5: Create account with wrong format of birthdate\n");
    account = account_create("user", "password", "user@example.com", "01-01-2000");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded");
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed");
        account_free(account);
    }

    log_message(LOG_INFO, "\nTest 6: Create account with empty username\n");
    account = account_create("", "password", "user@example.com", "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 7: Create account with empty password\n");
    account = account_create("user", "", "user@example.com", "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 8: Create account with empty email\n");
    account = account_create("user", "password", "", "2000-01-01");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 9: Create account with empty birthdate\n");
    account = account_create("user", "password", "user@example.com", "");
    if (account) {
        log_message(LOG_ERROR, "[FAIL] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[PASS] Account creation failed\n");
    }

    log_message(LOG_INFO, "\nTest 9: Create valid account\n");
    account = account_create("user", "password", "user@example.com", "2000-01-01");
    if (account) {
        log_message(LOG_INFO, "[PASS] Account creation succeeded\n");
        account_free(account);
    } else {
        log_message(LOG_INFO, "[FAIL] Account creation failed\n");
    }

    return 0;
}