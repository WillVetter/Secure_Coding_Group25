#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include "logging.h"
#include "login.h"
#include "db.h"
#include <sodium.h>

// Tests handle_login() is:
// 1) username, password, and session must be non-NULL.
// 2) username and password must be valid, null-terminated strings.
// 3) client_output_fd and log_fd must be valid file descriptors, open for writing.

// RUN in the terminal:
// gcc -std=c11 -pedantic-errors -Wall -Wextra -o test_handle_login tests/test_handle_login.c src/account.c src/stubs.c src/login.c -Isrc -lsodium
// ./test_handle_login

// Made these test cases adhere to the modified stubs.c file
int main() {
    // In case libsodium does not initalise
    if (sodium_init() == -1) {
        fprintf(stderr, "Failed to initialise libsodium\n");
        return 1;
    }

    account_t *account = account_create("bob", "newpass123", "test@example.com", "2000-01-01");
    login_session_data_t session;
    ip4_addr_t client_ip = 0x7F000001; // 127.0.0.1 in hex
    time_t login_time = time(NULL);
    login_result_t result;

    printf("\nTest 1: Successful login\n");
    result = handle_login("bob", "newpass123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_SUCCESS ? "[PASS]" : "[FAIL]");

    printf("\nTest 2: Wrong password\n");
    result = handle_login("bob", "wrongpassword", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_BAD_PASSWORD ? "[PASS]" : "[FAIL]");

    printf("\nTest 3: Username not found\n");
    result = handle_login("nonexistentuser", "newpass123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_USER_NOT_FOUND ? "[PASS]" : "[FAIL]");

    printf("\nTest 4: Username is NULL\n");
    result = handle_login(NULL, "newpass123", client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_USER_NOT_FOUND ? "[PASS]" : "[FAIL]");

    printf("\nTest 5: Password is NULL\n");
    result = handle_login("bob", NULL, client_ip, login_time, STDOUT_FILENO, &session);
    printf("%s\n", result == LOGIN_FAIL_BAD_PASSWORD ? "[PASS]" : "[FAIL]");

    // Not checking session in pre-condition. Passes when succeeds.
    printf("\nTest 6: Session is NULL)\n");
    result = handle_login("bob", "newpass123", client_ip, login_time, STDOUT_FILENO, NULL);
    printf("%s\n", result == LOGIN_SUCCESS ? "[PASS]" : "[FAIL]");

    account_free(account);
    return 0;
}