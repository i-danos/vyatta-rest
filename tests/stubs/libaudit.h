/* Test-only stand-in: libaudit-dev is not installed on the build host.
 * Only the one function authbasic.cc calls; the test provides the body. */
#ifndef STUB_LIBAUDIT_H
#define STUB_LIBAUDIT_H
#include <sys/types.h>
extern "C" int audit_setloginuid(uid_t uid);
#endif
