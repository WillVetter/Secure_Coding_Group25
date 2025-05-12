/**
 * @file alternate_main.c
 * @brief Standalone test harness for the handle_login function.
 */

#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <time.h>

#include "login.h"
#include "account.h"
#include "logging.h"
#include "db.h"
#include "banned.h"

/**
 * @brief Entry point of the standalone test for the login process.
 * @return Exit code 0 on success.
 */
int main() {
    login_session_data_t session;

    login_result_t result = handle_login("bob", "testpass", 0, time(NULL), STDOUT_FILENO, &session);

    if (result == LOGIN_SUCCESS) {
        dprintf(STDOUT_FILENO, "Login successful!\n");
        dprintf(STDOUT_FILENO, "Session info:\n");
        dprintf(STDOUT_FILENO, "  Account ID: %d\n", (int)session.account_id);
        dprintf(STDOUT_FILENO, "  Start Time: %ld\n", (long)session.session_start);
        dprintf(STDOUT_FILENO, "  Expiry Time: %ld\n", (long)session.expiration_time);
    } else {
        dprintf(STDOUT_FILENO, "Login failed with result code: %d\n", result);
    }

    return 0;
}
