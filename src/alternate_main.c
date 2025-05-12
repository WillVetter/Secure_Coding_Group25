#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <time.h>

#include "login.h"
#include "account.h"
#include "logging.h"
#include "db.h"

int main(void) {
    login_session_data_t session;
    time_t now = time(NULL);
    const char *userid = "bob";

    // Simulate 11 bad logins with wrong password
    for (int i = 1; i <= 11; i++) {
        dprintf(STDOUT_FILENO, "Attempt %d with bad password:\n", i);
        login_result_t res = handle_login(userid, "wrongpass", 0, now, STDOUT_FILENO, &session);
        if (res == LOGIN_FAIL_ACCOUNT_BANNED) {
            dprintf(STDOUT_FILENO, "Account was banned on attempt %d.\n", i);
            break;
        }
    }

    dprintf(STDOUT_FILENO, "\nNow trying the correct password (should fail if still banned):\n");
    login_result_t final_res = handle_login(userid, "testpass", 0, now, STDOUT_FILENO, &session);
    if (final_res == LOGIN_SUCCESS) {
        dprintf(STDOUT_FILENO, "Logged in successfully.\n");
    } else {
        dprintf(STDOUT_FILENO, "Login failed. Result code: %d\n", final_res);
    }

    return 0;
}
