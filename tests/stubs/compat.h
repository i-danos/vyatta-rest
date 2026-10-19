/* Force-included by the test build: authbasic.cc relies on headers and on
 * x_strdup() that its original (older) toolchain/common.hh pulled in. */
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
char *x_strdup(const char *s);
