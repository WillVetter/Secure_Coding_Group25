#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include "logging.h"
#include "login.h"
#include "db.h"
#include <string.h>
#include <sodium.h>

// Tests handle_login() is:
// 1) username, password, and session must be non-NULL.
// 2) username and password must be valid, null-terminated strings.
// 3) client_output_fd and log_fd must be valid file descriptors, open for writing.

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_handle_login tests/test_handle_login.c src/account.c src/login.c -Isrc -lsodium
// ./test_handle_login


static account_t *test_account = NULL; // For the mock account_lookup_by_userid

bool account_lookup_by_userid(const char *userid, account_t *acc) {
    if (!userid || !acc || !test_account) return false;
    if (strncmp(userid, test_account->userid, USER_ID_LENGTH) == 0) {
        *acc = *test_account;
        return true;
    }
    return false;
}

void log_message(log_level_t level, const char *fmt, ...) {
    const char *level_str = (level == LOG_ERROR) ? "ERROR" :
                            (level == LOG_WARN) ? "WARN" :
                            (level == LOG_INFO) ? "INFO" : "DEBUG";
    printf("[%s] ", level_str);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

int main() {
    if (sodium_init() == -1) {
        fprintf(stderr, "Failed to init libsodium\n");
        return 1;
    }

    account_t *account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    test_account = account;
    login_session_data_t session;
    ip4_addr_t client_ip = 0x7F000001; // 127.0.0.1
    time_t login_time = time(NULL);
    login_result_t result;

    printf("\nTest 1: Successful login\n");
    result = handle_login("testuser", "password123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_SUCCESS ? "PASS" : "FAIL");

    printf("\nTest 2: Incorrect password\n");
    result = handle_login("testuser", "wrongpassword", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_BAD_PASSWORD ? "PASS" : "FAIL");

    printf("\nTest 3: Non-existent username\n");
    result = handle_login("nonexistentuser", "password123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_USER_NOT_FOUND ? "PASS" : "FAIL");

    printf("\nTest 4: Locked account after 10 failed attempts\n");
    account->login_fail_count = 10; // simulate lockout
    result = handle_login("testuser", "password123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_ACCOUNT_BANNED ? "PASS" : "FAIL");
    account->login_fail_count = 0; // reset

    printf("\nTest 5: Expired account\n");
    account->expiration_time = login_time - 1; // expired
    result = handle_login("testuser", "password123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_ACCOUNT_EXPIRED ? "PASS" : "FAIL");
    account->expiration_time = login_time + 3600; // reset

    printf("\nTest 6: NULL username\n");
    result = handle_login(NULL, "password123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_USER_NOT_FOUND ? "PASS" : "FAIL");

    printf("\nTest 7: NULL password\n");
    result = handle_login("testuser", NULL, client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_BAD_PASSWORD ? "PASS" : "FAIL");

    printf("\nTest 8: NULL session (should still succeed)\n");
    result = handle_login("testuser", "password123", client_ip, login_time, STDOUT_FILENO, NULL);
    printf("%s\n", result == LOGIN_SUCCESS ? "PASS" : "FAIL");

    account_free(account);
    return 0;
}