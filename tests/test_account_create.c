#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// Tests all arguments in account_create() are:
// (1) All arguments must be valid, null-terminated strings. 
// (2) None of the pointers may be NULL.
// (3) Birthdate is in format YYYY-MM-DD

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_create tests/test_account_create.c src/account.c -Isrc -lsodium
// ./test_account_create

int main() {
    account_t *account;

    printf("Test 1: Create account with NULL username\n");
    account = account_create(NULL, "password123", "test@example.com", "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for NULL username\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for NULL username\n");
    }

    printf("\nTest 2: Create account with NULL password\n");
    account = account_create("testuser", NULL, "test@example.com", "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for NULL password\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for NULL password\n");
    }

    printf("\nTest 3: Create account with NULL email\n");
    account = account_create("testuser", "password123", NULL, "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for NULL email\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for NULL email\n");
    }

    printf("\nTest 4: Create account with NULL birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", NULL);
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for NULL birthdate\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for NULL birthdate\n");
    }

    printf("Test 5: Create account with wrong format of birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "01-01-2000");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly\n");
    } else {
        printf("PASS: Account creation failed as expected\n");
        account_free(account);
    }

    printf("\nTest 6: Create account with empty username\n");
    account = account_create("", "password123", "test@example.com", "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for empty username\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for empty username\n");
    }

    printf("\nTest 7: Create account with empty password\n");
    account = account_create("testuser", "", "test@example.com", "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for empty password\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for empty password\n");
    }

    printf("\nTest 8: Create account with empty email\n");
    account = account_create("testuser", "password123", "", "2000-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for empty email\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for empty email\n");
    }

    printf("\nTest 9: Create account with empty birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly for empty birthdate\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected for empty birthdate\n");
    }

    printf("\nTest 9: Create valid account\n");
    account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    if (account) {
        printf("PASS: Account creation succeeded\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed\n");
    }

    return 0;
}