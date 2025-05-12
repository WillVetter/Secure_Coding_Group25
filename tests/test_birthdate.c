#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdarg.h>

// gcc -o test_birthdate tests/test_birthdate.c src/account.c -Isrc -lsodium
int main() {
    account_t *account;

    printf("Test 1: Create account with over 100 year old birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "1924-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected\n");
    }

    printf("\nTest 2: Create account with under 13 year old birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "2017-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected\n");
    }

    printf("\nTest 3: Create account with birthdate from the future\n");
    account = account_create("testuser", "password123", "test@example.com", "2026-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected\n");
    }

    printf("\nTest 4: Create account with valid birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    if (account) {
        printf("PASS: Account creation succeeded as expected\n");
        account_free(account);
    } else {
        printf("FAIL: Account creation failed unexpectedly\n");
    }

    printf("Test 5: Create account with over 100 year old birthdate\n");
    account = account_create("testuser", "password123", "test@example.com", "1924-01-01");
    if (account) {
        printf("FAIL: Account creation succeeded unexpectedly\n");
        account_free(account);
    } else {
        printf("PASS: Account creation failed as expected\n");
    }

    return 0;
}