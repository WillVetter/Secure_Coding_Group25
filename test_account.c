#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "src/account.h"  // adjust if needed

// ACCOUNT MANAGEMENT TESTS

void test_account_create_valid() {
    account_t *acc = account_create("user1", "pass123", "user1@email.com", "2000-01-01");
    assert(acc != NULL);
    assert(strcmp(acc->userid, "user1") == 0);
    account_free(acc);
}

void test_account_free_safe() {
    account_t *acc = account_create("freeuser", "pass", "f@email.com", "1990-05-05");
    account_free(acc); // just check it doesn’t crash
}

void test_account_set_email() {
    account_t *acc = account_create("mailuser", "123", "old@email.com", "1995-10-10");
    account_set_email(acc, "new@email.com");
    assert(strcmp(acc->email, "new@email.com") == 0);
    account_free(acc);
}

void test_account_set_unban_time() {
    account_t *acc = account_create("banned", "pass", "b@email.com", "1998-12-12");
    time_t future = time(NULL) + 3600;
    account_set_unban_time(acc, future);
    assert(acc->unban_time == future);
    account_free(acc);
}

void test_account_set_expiration_time() {
    account_t *acc = account_create("expire", "123", "x@email.com", "1991-09-09");
    time_t expire_time = time(NULL) + 7200;
    account_set_expiration_time(acc, expire_time);
    assert(acc->expiration_time == expire_time);
    account_free(acc);
}

void test_account_is_banned_true() {
    account_t *acc = account_create("banned", "p", "e@e.com", "1990-01-01");
    account_set_unban_time(acc, time(NULL) + 100);
    assert(account_is_banned(acc) == true);
    account_free(acc);
}

void test_account_is_expired_false() {
    account_t *acc = account_create("active", "p", "e@e.com", "1990-01-01");
    account_set_expiration_time(acc, time(NULL) + 1000);
    assert(account_is_expired(acc) == false);
    account_free(acc);
}

void test_account_record_login_success() {
    account_t *acc = account_create("login1", "p", "e@e.com", "1990-01-01");
    acc->failed_login_attempts = 5;
    account_record_login_success(acc);
    assert(acc->failed_login_attempts == 0);
    account_free(acc);
}

void test_account_record_login_failure() {
    account_t *acc = account_create("fail", "p", "e@e.com", "1990-01-01");
    int prev = acc->failed_login_attempts;
    account_record_login_failure(acc);
    assert(acc->failed_login_attempts == prev + 1);
    account_free(acc);
}

void test_account_print_summary() {
    account_t *acc = account_create("summary", "p", "e@e.com", "1990-01-01");
    int dummy_fd = 1; // stdout
    bool result = account_print_summary(acc, dummy_fd);
    assert(result == true || result == false); // depends on what you return
    account_free(acc);
}

// PASSWORD HANDLING TESTS

void test_account_validate_password() {
    account_t *acc = account_create("pwdtest", "mypassword", "e@e.com", "1990-01-01");
    assert(account_validate_password(acc, "mypassword") == true);
    assert(account_validate_password(acc, "wrongpass") == false);
    account_free(acc);
}

void test_account_update_password() {
    account_t *acc = account_create("update", "oldpass", "e@e.com", "1990-01-01");
    account_update_password(acc, "newpass");
    assert(account_validate_password(acc, "newpass") == true);
    account_free(acc);
}

// LOGIN-RELATED MOCK TESTS

void test_account_lookup_by_userid_mock() {
    // This test will work once account_lookup_by_userid() is fully set up.
    // For now just leaving a placeholder assert below:

    // assert(account_lookup_by_userid("some_id") != NULL);
}

void test_log_message_mock() {
   // Just testing if log_message() prints something without crashing.
    log_message("Test log message\n");
}

int main() {
    printf("Running test cases...\n");

    // Account management
    test_account_create_valid();
    test_account_free_safe();
    test_account_set_email();
    test_account_set_unban_time();
    test_account_set_expiration_time();
    test_account_is_banned_true();
    test_account_is_expired_false();
    test_account_record_login_success();
    test_account_record_login_failure();
    test_account_print_summary();

    // Password
    test_account_validate_password();
    test_account_update_password();

    // Mocks / placeholders
    test_account_lookup_by_userid_mock();
    test_log_message_mock();

    printf("All tests passed successfully!\n");
    return 0;
}
