#include "account.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <crypt.h>

//Remove below if not needed (only used for logging)
#include <arpa/inet.h>

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
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

    char *hash = hash_password(plaintext_password);
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

void account_free(account_t *acc) {
    if (!acc) return;

    // Free dynamically allocated fields if they exist
    if (acc->last_ip) {};// free(acc->last_ip); // Or did you mean to use last_login_time?

    free(acc);
}

bool account_validate_password(const account_t *acc, const char *plaintext_password) { 

  //check acc and plaintext are non null, plaintext valid null terminated string
  if (!acc || !plaintext_password ) {
        log_message(LOG_ERROR, "account_validate_password: NULL argument");
        return NULL;
  }

  char *hash = hash_password(plaintext_password);

  for (unsigned long i = 0; i < strlen(acc->password_hash); i++){ 
    if (hash[i] != acc->password_hash[i]) {
      log_message(LOG_ERROR, "account_validate_password: incorrect password");
      free(hash); 
      return false; 
    } 
  }

  log_message(LOG_ERROR, "account_validate_password: correct password");
  free(hash);
  return true; 
}


bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    if (!acc) return;

    acc->login_fail_count = 0;
    acc->last_ip = ip;
    acc->last_login_time = time(NULL);

    //This is all part of the same log functionality
    char ip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP string
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    log_message(LOG_INFO, "Successful login for user %s from %s",
                acc->userid, ip_str);
}


void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  if (!acc) {
      log_message(LOG_ERROR, "account_record_login_failure: NULL argument");
      return;
  }
  acc->login_count = 0; 
}

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

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
    if (!acc) return;
    acc->expiration_time = t;
}

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


bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

