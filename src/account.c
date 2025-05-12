/**
 * @file account.c
 * @brief This file handles user account creation, password management, login tracking, and account state checks.
 */
#include "account.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <crypt.h>
#include <sodium.h>
#include <unistd.h>
#include <arpa/inet.h>

/**
 * @brief Hash a plaintext password using Argon2id.
 * @param plaintext_password The plaintext password to hash.
 * @return A string containing the hashed password, or NULL on failure.
 */
char* hashPassword(const char* plaintext_password) {

    if (!plaintext_password) {
        log_message(LOG_ERROR, "hash_password: NULL password provided");
        return NULL;
    }

    if (sodium_init() < 0) {
        log_message(LOG_ERROR, "Failed to hash password: libsodium initialization failed");
        return NULL;
    }
    char* hashed_password = malloc(crypto_pwhash_STRBYTES);
    if (!hashed_password) {
        log_message(LOG_ERROR, "Failed to hash password: memory allocation failed");
        return NULL;
    }

    if (crypto_pwhash_str(
        hashed_password,
        plaintext_password,
        strlen(plaintext_password),
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        log_message(LOG_ERROR, "hash_password: password hashing failed");
        free(hashed_password);
        return NULL;
    }

    return hashed_password;
}

/**
 * @brief Create a new account with the specified parameters.
 * @param userid The user ID for the account.
 * @param plaintext_password The plaintext password for the account.
 * @param email The email address for the account.
 * @param birthdate The birthdate for the account in the format "YYYY-MM-DD".
 * @return A pointer to the newly created account structure, or NULL on error.
 */
account_t *account_create(const char *userid, const char *plaintext_password, 
    const char *email, const char *birthdate)
{
    if (!userid || !plaintext_password || !email || !birthdate) {
        log_message(LOG_ERROR, "account_create: NULL argument");
        return NULL;
    }

    size_t uid_len = strlen(userid);
    if (uid_len == 0 || uid_len >= USER_ID_LENGTH) {
        log_message(LOG_ERROR, "account_create: invalid userid length");
        return NULL;
    }

    size_t em_len = strlen(email);
    if (em_len == 0 || em_len >= EMAIL_LENGTH) {
        log_message(LOG_ERROR, "account_create: invalid email length");
        return NULL;
    }

    for (size_t i = 0; i < em_len; ++i) {
        unsigned char c = (unsigned char)email[i];
        if (!isprint(c) || isspace(c)) {
            log_message(LOG_ERROR, "account_create: invalid email format");
            return NULL;
        }
    }

    if (strlen(birthdate) != 10 || birthdate[4] != '-' || birthdate[7] != '-') {
        log_message(LOG_ERROR, "account_create: invalid birthdate format");
        return NULL;
    }
    for (int i = 0; i < 10; ++i) {
        if (i == 4 || i == 7) continue;
        if (!isdigit((unsigned char)birthdate[i])) {
            log_message(LOG_ERROR, "account_create: invalid birthdate digits");
            return NULL;
        }
    }

    char *hash = hashPassword(plaintext_password);
    if (!hash) {
        log_message(LOG_ERROR, "account_create: password hashing returned NULL");
        return NULL;
    }

    account_t *acc = calloc(1, sizeof(*acc));
    if (!acc) {
        log_message(LOG_ERROR, "account_create: allocation failed: %s", strerror(errno));
        free(hash);
        return NULL;
    }

    strncpy(acc->userid, userid, USER_ID_LENGTH);
    acc->userid[USER_ID_LENGTH - 1] = '\0';

    strncpy(acc->password_hash, hash, HASH_LENGTH);
    acc->password_hash[HASH_LENGTH - 1] = '\0';
    free(hash);

    strncpy(acc->email, email, EMAIL_LENGTH);
    acc->email[EMAIL_LENGTH - 1] = '\0';

    strncpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH);
    acc->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

    return acc;
}

/**
 * @brief Free the memory allocated for an account.
 * @param acc The account to free.
 */
void account_free(account_t *acc) {
    if (!acc) return;

    if (acc->last_ip) {};

    free(acc);
}


/**
* @brief Validate the plaintext password with the hash stored for an account.
* @param acc The account to validate the password against.
* @param plaintext_password The plaintext password to validate.
* @return true if the password matches, false otherwise.
*/
bool account_validate_password(const account_t *acc, const char *plaintext_password) {
    if (!acc || !plaintext_password) {
        log_message(LOG_ERROR, "account_validate_password: NULL argument provided");
        return false;
    }
    if (crypto_pwhash_str_verify(acc->password_hash, plaintext_password, strlen(plaintext_password)) != 0) {
        log_message(LOG_ERROR, "account_validate_password: password verification failed for user %s", acc->userid);
        return false;
    }

    log_message(LOG_INFO, "account_validate_password: password verification succeeded for user %s", acc->userid);
    return true;
}

/**
* @brief Update the password for an account with a new plaintext password.
* @param acc The account to update.
* @param new_plaintext_password The new plaintext password to set.
* @return true on success, false on failure.
*/
bool account_update_password(account_t *acc, const char *new_plaintext_password) {
    if (!acc || !new_plaintext_password) {
        log_message(LOG_ERROR, "account_update_password: NULL argument provided");
        return false;
    }

    char *new_hash = hashPassword(new_plaintext_password);
    if (!new_hash) {
        log_message(LOG_ERROR, "account_update_password: password hashing failed for user %s", acc->userid);
        return false;
    }

    strncpy(acc->password_hash, new_hash, HASH_LENGTH);
    acc->password_hash[HASH_LENGTH - 1] = '\0';

    free(new_hash);

    log_message(LOG_INFO, "account_update_password: password updated successfully for user %s", acc->userid);
    return true;
  
}

/**
 * @brief Record a successful login for an account.
 * @param acc The account to update.
 * @param ip The IP address of the successful login.
 */
void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    if (!acc) return;

    acc->login_fail_count = 0;
    acc->last_ip = ip;
    acc->last_login_time = time(NULL);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    log_message(LOG_INFO, "Successful login for user %s from %s",
                acc->userid, ip_str);
}

/**
 * @brief Record a failed login attempt for an account.
 * @param acc The account to update.
 */
void account_record_login_failure(account_t *acc) {
    if (!acc) {
        log_message(LOG_ERROR, "account_record_login_failure: NULL argument");
        return;
    }
    acc->login_count = 0; 
}

/**
 * @brief Check if an account is banned.
 * @param acc The account to check.
 * @return true if the account is banned, false otherwise.
 */
bool account_is_banned(const account_t *acc) { 

    if (!acc) {
        log_message(LOG_ERROR, "account_is_banned: NULL argument");
        return NULL;
    }

    if (acc->unban_time == 0) {
        log_message(LOG_INFO, "account is banned: %ld \n", acc->unban_time);
        return false; 
    } 
    else {
        return true; 
    }
}

/**
 * @brief Check if an account is expired.
 * @param acc The account to check.
 * @return true if the account is expired, false otherwise.
 */
bool account_is_expired(const account_t *acc) {
    time_t current_time = time(NULL);
    if (acc->expiration_time != 0 && current_time >= acc->expiration_time) {
        log_message(LOG_INFO, "account_is_expired: Account %s is expired", acc->userid);
        return true;
    }

    return false;
}

/**
 * @brief Set the unban time for an account.
 * @param acc The account to update.
 * @param t The new unban time.
 */
void account_set_unban_time(account_t *acc, time_t t) {
    acc->unban_time = t;

    log_message(LOG_INFO, "account_set_unban_time: Unban time set to %ld for user %s", 
                (long)t, acc->userid);
}

/**
 * @brief Set the expiration time for an account.
 * @param acc The account to update.
 * @param t The new expiration time.
 */
void account_set_expiration_time(account_t *acc, time_t t) {
    if (!acc) return;
    acc->expiration_time = t;
}

/**
 * @brief Update the email address for an account.
 * @param acc The account to update.
 * @param new_email The new email address to set.
 */
void account_set_email(account_t *acc, const char *new_email) {

    if (!acc || !new_email ) {
            log_message(LOG_ERROR, "account_set_email: NULL argument");
            return;
    }

    size_t em_len = strlen(new_email);
    if (em_len == 0 || em_len >= EMAIL_LENGTH) {
        log_message(LOG_ERROR, "account_set_email: invalid email length");
        return;
    }

    for (size_t i = 0; i < em_len; ++i) {
        unsigned char c = (unsigned char)new_email[i];
        if (!isprint(c) || isspace(c)) {
            log_message(LOG_ERROR, "account_set_email: invalid email format");
            return;
        }
    }

    strncpy(acc->email, new_email, EMAIL_LENGTH);
    acc->email[EMAIL_LENGTH - 1] = '\0';
}

/**
 * @brief Print a summary of the account to a file descriptor.
 * @param acct The account to summarize.
 * @param fd The file descriptor to write the summary to.
 * @return true on success, false on failure.
 */
bool account_print_summary(const account_t *acct, int fd) {
    if (!acct) {
        log_message(LOG_ERROR, "account_print_summary: NULL account pointer");
        return false;
    }

    if (fd < 0) {
        log_message(LOG_ERROR, "account_print_summary: Invalid file descriptor");
        return false;
    }

    char summary[512];
    char ip_str[INET_ADDRSTRLEN] = "N/A";

    if (acct->last_ip != 0) {
        inet_ntop(AF_INET, &acct->last_ip, ip_str, INET_ADDRSTRLEN);
    }

    int written = snprintf(summary, sizeof(summary),
        "User ID: %s\n"
        "Email: %s\n"
        "Login Failures: %u\n"
        "Last Login Time: %ld\n"
        "Last Login IP: %s\n"
        "Unban Time: %ld\n"
        "Expiration Time: %ld\n",
        acct->userid,
        acct->email,
        acct->login_fail_count,
        (long)acct->last_login_time,
        ip_str,
        (long)acct->unban_time,
        (long)acct->expiration_time
    );

    if (written < 0 || (size_t)written >= sizeof(summary)) {
        log_message(LOG_ERROR, "account_print_summary: Failed to format summary");
        return false;
    }

    if (write(fd, summary, written) != written) {
        log_message(LOG_ERROR, "account_print_summary: Failed to write summary to file descriptor");
        return false;
    }

    return true;
}
