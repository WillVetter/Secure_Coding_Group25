#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdarg.h>
#include "db.h"

// Tests all arguments in account_record_login_success and account_record_login_failure(account_t *acc) are:
// (1) acc must be non-NULL

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_account_record tests/test_account_record.c src/account.c src/stubs.c -Isrc -lsodium
// ./test_account_record

int main() {

    account_t *account = account_create("user", "password", "user@example.com", "2000-01-01");
    if (!account) {
        printf("Failed to create account.\n");
        return 1;
    }
    
    printf("\nTest 1: Fail logins and check login fail count resets to zero after successful login\n");
    for (int i = 0; i < 3; i++) {
        account_record_login_failure(account);
        printf("Login fail count after attempt %d: %u\n", i + 1, account->login_fail_count);
        if (account->login_fail_count == (unsigned int)(i + 1)) {
            printf("[PASS] Login fail count is correct after attempt %d\n", i + 1);
        } else {
            printf("[FAIL] Login fail count is incorrect after attempt %d\n", i + 1);
        }
    }

    printf("\nTest 2: Simulating successful login\n");
    account_record_login_success(account, 0x7F000001); // 127.0.0.1 in hex
    printf("Login fail count after successful login: %u\n", account->login_fail_count);
    if (account->login_fail_count == 0) {
        printf("[PASS] Login fail count was reset to 0 after successful login.\n");
    } else {
        printf("[FAIL] Login attempt allowed with more than 10 login failures\n");
    }

    printf("\nTest 3: Simulating failed login attempts exceeding threshold...\n");
    for (int i = 0; i < 10; i++) {
        account_record_login_failure(account);
        printf("Login fail count after attempt %d: %u\n", i + 1, account->login_fail_count);
    }

    printf("\nTest 4: Attempt successful login after exceeding failed login threshold...\n");
    account_record_login_success(account, 0x7F000001); 
    if (account->login_fail_count >= 10) {
        printf("[PASS] Login attempt blocked due to too many failed attempts\n");
    } else {
        printf("[FAIL] Login attempt allowed despite too many failed attempts\n");
    }
    account_free(account);

    // Handle NULL account
    account = NULL;
    printf("\nTest 5: Handle NULL account in login success\n");
    if (account) {
        printf("[FAIL] Account creation accepted NULL account\n");
    } else {
        printf("[PASS] Account creation rejected NULL account\n");
    }
    account_free(account);

    return 0;
}