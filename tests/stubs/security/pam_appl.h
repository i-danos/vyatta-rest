/* Test-only stand-in for <security/pam_appl.h> (libpam0g-dev not installed).
 * Declares just what authbasic.cc uses; the test provides every body. */
#ifndef STUB_PAM_APPL_H
#define STUB_PAM_APPL_H
#include <stddef.h>
#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 7
#define PAM_BUF_ERR 5
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_PROMPT_ECHO_ON 2
#define PAM_ERROR_MSG 3
#define PAM_TEXT_INFO 4
struct pam_message { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv {
	int (*conv)(int, const struct pam_message **, struct pam_response **, void *);
	void *appdata_ptr;
};
typedef struct pam_handle pam_handle_t;
extern "C" {
int pam_start(const char *, const char *, const struct pam_conv *, pam_handle_t **);
int pam_authenticate(pam_handle_t *, int);
int pam_acct_mgmt(pam_handle_t *, int);
int pam_end(pam_handle_t *, int);
}
#endif
