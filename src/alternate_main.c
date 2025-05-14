#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <time.h>
#include <string.h>

#include "login.h"
#include "account.h"
#include "logging.h"
#include "db.h"
#include "banned.h"

// Get readable time for start time and expiry time
static void get_readable_time(time_t t, char *buffer, size_t size) {
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "Unknown time", size);
        buffer[size - 1] = '\0'; // Prevents buffer overflow
    }
}


int main() {
    login_session_data_t session;

    // Lookup account and update password before login
    account_t user;
    if (account_lookup_by_userid("bob", &user)) {
        if (account_update_password(&user, "newpass123")) {
            dprintf(STDOUT_FILENO, "Password for bob updated to 'newpass123'\n");
        } else {
            dprintf(STDOUT_FILENO, "Failed to update password for bob\n");
        }
    } else {
        dprintf(STDOUT_FILENO, "User 'bob' not found\n");
    }
 

    // Test login with new password
    login_result_t result = handle_login("bob", "newpass123", 0, time(NULL), STDOUT_FILENO, &session);

    if (result == LOGIN_SUCCESS) {
        char start_time_str[64];
        char expiry_time_str[64];

        get_readable_time(session.session_start, start_time_str, sizeof(start_time_str));
        get_readable_time(session.expiration_time, expiry_time_str, sizeof(expiry_time_str));
        
        dprintf(STDOUT_FILENO, "Login successful!\n");
        dprintf(STDOUT_FILENO, "Session info:\n");
        dprintf(STDOUT_FILENO, "  Account ID: %d\n", (int)session.account_id);
        dprintf(STDOUT_FILENO, "  Start Time: %s\n", start_time_str);
        dprintf(STDOUT_FILENO, "  Expiry Time: %s\n", expiry_time_str);
    } else {
        dprintf(STDOUT_FILENO, "Login failed with result code: %d\n", result);
    }

    return 0;
}
