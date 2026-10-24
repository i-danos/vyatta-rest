// Runtime regression for A04: with debug enabled, neither a successful nor a
// failed Basic authentication may write the raw, decoded, base64 or otherwise
// reversible password to the log. Compiles the real authbasic.cc; the log sink
// (syslog/vsyslog), PAM, audit and the account database are replaced by
// recording stubs. Build/run: tests/run-auth-debug-logging-test.sh
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <libaudit.h>
#include "http.hh"
#include "authbasic.hh"
#include "authsession.hh"
#include "authenticate.hh"

// ---- captured log -------------------------------------------------------
static std::string g_log;
extern "C" void vsyslog(int, const char *fmt, va_list ap) {
	char buf[4096];
	vsnprintf(buf, sizeof buf, fmt, ap);
	g_log += buf; g_log += '\n';
}
extern "C" void syslog(int pri, const char *fmt, ...) {
	va_list ap; va_start(ap, fmt); vsyslog(pri, fmt, ap); va_end(ap);
}

// ---- collaborators the real file links against ---------------------------
char *x_strdup(const char *s) { return strdup(s); }  // declared in compat.h
const std::string Rest::AUTH_BASIC = "Basic";
const std::string Rest::PRAGMA_SERVICE_USER = "vyatta-service-user";
std::string Rest::SERVICE_REQ_ROOT = "/rest/service";
#include <map>
static std::map<const HTTP *, std::map<int, std::string>> g_http;  // HTTP's own map is private
std::string HTTP::get(Rest::KEY k) { auto &m = g_http[this]; auto i = m.find((int)k); return i == m.end() ? "" : i->second; }
void HTTP::set(Rest::KEY k, const std::string &v) { g_http[this][(int)k] = v; }
void HTTP::set(Rest::KEY k, const char *v) { set(k, std::string(v)); }
void HTTP::append(Rest::KEY, const std::string &) {}
// what Session::vyatta_debug() puts into the response "vyatta-debug" header; main.cc logs the
// whole serialized response (AUTHFAILED) and sends it to the client, so it counts as log output
static std::string g_dbg;
void Session::vyatta_debug(const std::string &d) { if (_debug) { g_dbg += d; g_dbg += '\n'; } }
// AuthSession is not under test here (the Authenticate collection only needs it to link)
AuthSession::AuthSession(bool d) : AuthBase(d) {}
bool AuthSession::handle(const std::string &) { return false; }
bool AuthSession::authorized(const std::string &, Session &) { return false; }

static bool g_pam_ok = true;
static std::string g_pam_password;       // what PAM was actually handed
extern "C" {
int pam_start(const char *, const char *, const struct pam_conv *c, pam_handle_t **h) {
	*h = (pam_handle_t *)0x1;
	struct pam_message m = {PAM_PROMPT_ECHO_OFF, "Password:"};
	const struct pam_message *mp = &m;
	struct pam_response *r = nullptr;
	c->conv(1, &mp, &r, c->appdata_ptr);
	g_pam_password = r ? r[0].resp : "";
	return PAM_SUCCESS;
}
int pam_authenticate(pam_handle_t *, int) { return g_pam_ok ? PAM_SUCCESS : PAM_AUTH_ERR; }
int pam_acct_mgmt(pam_handle_t *, int) { return PAM_SUCCESS; }
int pam_end(pam_handle_t *, int) { return PAM_SUCCESS; }
int audit_setloginuid(uid_t) { return 0; }
}
static struct passwd g_pw = {(char *)"alice", (char *)"x", 1001, 1001, (char *)"", (char *)"/", (char *)"/bin/sh"};
struct passwd *getpwnam(const char *n) { return strcmp(n, "alice") == 0 ? &g_pw : nullptr; }
int getgrouplist(const char *, gid_t g, gid_t *gs, int *n) { gs[0] = g; *n = 1; return 1; }
struct group *getgrgid(gid_t) { return nullptr; }
int setgroups(size_t, const gid_t *) { return 0; }
int setegid(gid_t) { return 0; }
int seteuid(uid_t) { return 0; }

// ---- helpers -------------------------------------------------------------
static std::string b64(const std::string &in) {
	static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out; int val = 0, bits = -6;
	for (unsigned char c : in) { val = (val << 8) + c; bits += 8;
		while (bits >= 0) { out += t[(val >> bits) & 0x3F]; bits -= 6; } }
	if (bits > -6) out += t[((val << 8) >> (bits + 8)) & 0x3F];
	while (out.size() % 4) out += '=';
	return out;
}

static int failures = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL %s\n", msg); ++failures; } else printf("ok   %s\n", msg); } while (0)

// log must not contain secret in any of: raw, base64 of "user:secret", base64 of secret
static void check_no_secret(const std::string &user, const std::string &secret, const char *what) {
	std::string a = b64(user + ":" + secret), b = b64(secret);
	std::string all = g_log + g_dbg;   // log text plus the vyatta-debug header text
	CHECK(all.find(secret) == std::string::npos, (std::string(what) + ": raw password not logged").c_str());
	CHECK(all.find(a) == std::string::npos, (std::string(what) + ": base64 user:password not logged").c_str());
	CHECK(all.find(b) == std::string::npos, (std::string(what) + ": base64 password not logged").c_str());
	CHECK(all.find(user + ":" + secret) == std::string::npos, (std::string(what) + ": decoded credentials not logged").c_str());
}

static bool run(bool debug, bool pam_ok, bool service, const std::string &user, const std::string &pw) {
	g_http.clear(); g_log.clear(); g_dbg.clear(); g_pam_ok = pam_ok; g_pam_password.clear();
	AuthBasic ab(debug);
	Session s(debug);
	if (service) s._request.set(Rest::HTTP_REQ_URI, "/rest/service/x");
	return ab.authorized("Basic " + b64(user + ":" + pw), s);
}

int main() {
	const std::string secret = "Zx9!hunter2-Q";

	bool ok = run(true, true, false, "alice", secret);
	CHECK(ok, "debug on, correct password: authentication succeeds");
	CHECK(g_pam_password == secret, "debug on, success: PAM still receives the real password");
	CHECK(g_log.find("auth") != std::string::npos, "debug on, success: debug logging is active (control)");
	check_no_secret("alice", secret, "success");

	bool bad = run(true, false, false, "alice", secret);
	CHECK(!bad, "debug on, wrong password: authentication fails");
	CHECK(g_log.find("failed on pam_authenticate") != std::string::npos, "debug on, failure: failure path was logged (control)");
	check_no_secret("alice", secret, "failure");

	bool svc = run(true, false, true, "svcuser", secret);
	CHECK(!svc, "debug on, service user, wrong password: fails");
	check_no_secret("svcuser", secret, "service-user failure");

	bool unknown = run(true, true, false, "nobody", secret);
	CHECK(!unknown, "debug on, unknown account: fails");
	check_no_secret("nobody", secret, "unknown-user failure");

	bool nodbg = run(false, true, false, "alice", secret);
	CHECK(nodbg && g_log.empty(), "debug off: succeeds and logs nothing");

	// Full path: Authenticate::validate() with the real Authorization header, as lighttpd passes it.
	// The pre-fix code put "AAAA:<header>" (base64 of user:password) into the debug text.
	{
		g_http.clear(); g_log.clear(); g_dbg.clear(); g_pam_ok = false;
		Authenticate au(true);
		Session s(true);
		const std::string hdr = "Basic " + b64("alice:" + secret);
		s._request.set(Rest::HTTP_REQ_AUTHORIZATION, hdr);
		bool r = au.validate(s);
		CHECK(!r, "validate(), debug on, wrong password: fails");
		CHECK(g_dbg.find("AAAA") != std::string::npos, "validate(): debug header text is produced (control)");
		CHECK(g_dbg.find(hdr) == std::string::npos, "validate(): Authorization header value not in debug text");
		CHECK(g_dbg.find(b64("alice:" + secret)) == std::string::npos, "validate(): base64 user:password not in debug text");
		check_no_secret("alice", secret, "validate() failure");
		CHECK(g_log.find("alice") != std::string::npos, "validate(): username is still logged (auth2a)");
	}
	{
		g_http.clear(); g_log.clear(); g_dbg.clear();
		Authenticate au(true);
		Session s(true);
		const std::string cookie = "Vyatta-Session 0123456789abcdef";
		s._request.set(Rest::HTTP_REQ_COOKIE, cookie);
		au.validate(s);
		CHECK(g_dbg.find("0123456789abcdef") == std::string::npos, "validate(): session cookie key not in debug text");
	}

	printf(failures ? "%d failed\n" : "all passed\n", failures);
	return failures != 0;
}
