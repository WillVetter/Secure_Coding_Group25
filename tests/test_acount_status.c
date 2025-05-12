#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "account.h"
#include <sodium.h>
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

// gcc -o test_account_status tests/test_account_status.c src/account.c -Isrc -lsodium

void log_message(log_level_t level, const char *fmt, ...) {
    const char *level_str;
    switch (level) {
        case LOG_DEBUG:
            level_str = "DEBUG";
            break;
        case LOG_INFO:
            level_str = "INFO";
            break;
        case LOG_WARN:
            level_str = "WARN";
            break;
        case LOG_ERROR:
            level_str = "ERROR";
            break;
        default:
            level_str = "UNKNOWN";
            break;
    }

    printf("[%s] ", level_str);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}


int main() {
    printf("Test 1: Check banned status for a banned account\n");
    account_t *account = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    account_set_banned(account, true); // Use the setter function to simulate a banned account
    if (account_is_banned(account)) {
        printf("Account is correctly identified as banned!\n");
    } else {
        printf("Account is not identified as banned!\n");
    }

    account_free(account);
    return 0;
}