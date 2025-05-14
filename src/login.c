/**
 * @file login.c
 * @brief Implements the login handler, including account lookup, validation, and session initialization.
 */

#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include "login.h"
#include "logging.h"
#include "db.h"
#include "banned.h"

// 2 hour session duration. Would change depending on policy.
#define SESSION_DURATION_LIMIT (2 * 3600)
// MIN 10 minutes auto-ban duration. Would change depending on policy.
#define AUTO_BAN_DURATION (10 * 60)
#define MAX_LOGIN_RETRIES 10
#define TIMESTAMP_BUFFER 26

/**
 * @brief Convert a `time_t` value into a human-readable string.
 * @param t The time to convert.
 * @param buffer The buffer to store the formatted time string.
 * @param size The size of the buffer.
 */
static void get_readable_time(time_t t, char *buffer, size_t size) {
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "Unknown time", size);
        buffer[size - 1] = '\0'; // Prevents buffer overflow
    }
}

/**
 * @brief Handle the login process for a user, including authentication and session creation.
 * @param userid The user ID attempting to log in.
 * @param password The plaintext password provided by the user.
 * @param client_ip The IP address of the client attempting to log in.
 * @param login_time The current time when the login is attempted.
 * @param client_output_fd File descriptor to send login feedback to the user.
 * @param session Pointer to the session structure to populate upon successful login.
 * @return A login_result_t code indicating the result of the login attempt.
 */
login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session) {
    char now_str[TIMESTAMP_BUFFER];
    char unban_str[TIMESTAMP_BUFFER];
    char ip_str[STRINGIFY_IP_BUFFER];

    time_t now = login_time;
    get_readable_time(now, now_str, sizeof(now_str));
    ip4_to_string(client_ip, ip_str, sizeof(ip_str));

    // Username is NULL
    if (!userid) {
        dprintf(client_output_fd, "Login failed: Username is required\n");
        log_message(LOG_ERROR, "handle_login: Username is NULL");
        return LOGIN_FAIL_USER_NOT_FOUND;
    }

    // Password is NULL
    if (!password) {
        dprintf(client_output_fd, "Login failed: Password is required\n");
        log_message(LOG_ERROR, "handle_login: Password is NULL");
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    if (!validate_input(password)) {
      log_message(LOG_ERROR, "handle_login: invalid input. Only alphanumeric characters, _, @, ., -, + are allowed");
      return LOGIN_FAIL_BAD_PASSWORD;
    }

    // User cannot be found
    account_t user_account_buf;
    if (!account_lookup_by_userid(userid, &user_account_buf)) {
        dprintf(client_output_fd, "Login failed: User not found\n");
        log_message(LOG_INFO, "Login failed: Unknown user %s\n", userid);
        return LOGIN_FAIL_USER_NOT_FOUND;
    }
    account_t *user_account = &user_account_buf;

    // Account is banned
    if (user_account->unban_time > now) {
        get_readable_time(user_account->unban_time, unban_str, sizeof(unban_str));
        dprintf(client_output_fd, 
                "Account Banned: Too many failed login attempts. Try again after %s\n", unban_str);
        log_message(LOG_WARN, "Login attempt by banned user %s from IP %s at %s\n", userid, ip_str, now_str);
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    // Account is expired
    if (account_is_expired(user_account)) {
        dprintf(client_output_fd, "Login failed: Account is expired\n");
        log_message(LOG_WARN, "Login attempt by expired user %s from IP %s at %s\n", userid, ip_str, now_str);
        return LOGIN_FAIL_ACCOUNT_EXPIRED;
    }

    // Account fails to login 10 consecutive times
    if (user_account->login_fail_count >= MAX_LOGIN_RETRIES) {
        time_t unban_at = now + AUTO_BAN_DURATION;
        get_readable_time(unban_at, unban_str, sizeof(unban_str));

        dprintf(client_output_fd, 
                "Account Banned: Too many failed login attempts. Try again after %s\n", unban_str);
        log_message(LOG_WARN, "User %s banned after excessive failures from IP %s at %s until %s\n",
                    userid, ip_str, now_str, unban_str);

        account_set_unban_time(user_account, unban_at);
        user_account->login_fail_count = 0;
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    // Validates the password when logging in
    if (!account_validate_password(user_account, password)) {
        account_record_login_failure(user_account);

        int remaining = MAX_LOGIN_RETRIES - user_account->login_fail_count;
        dprintf(client_output_fd,
                "Login failed: Please ensure your details are correct.\nAttempts remaining: %d\n",
                remaining);

        log_message(LOG_INFO, "Login failed: Bad password for user %s from IP %s at %s\n",
                    userid, ip_str, now_str);
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    // User successfully logins
    account_record_login_success(user_account, client_ip);

    if (session) {
        session->account_id = user_account->account_id;
        session->session_start = user_account->last_login_time;
        session->expiration_time = user_account->last_login_time + SESSION_DURATION_LIMIT;
    }

    dprintf(client_output_fd, "Login successful: Welcome %s\n", userid);
    log_message(LOG_INFO, "User %s logged in from IP %s at %s\n", userid, ip_str, now_str);

    return LOGIN_SUCCESS;
}