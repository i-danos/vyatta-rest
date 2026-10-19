/**
 * Module: authenticate.cc
 * Description: Authentication support
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2009-2013 Vyatta, Inc.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 **/

#include <libaudit.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <errno.h>
#include "common.hh"
#include "authbase.hh"
#include "authbasic.hh"

#include "debug.h"

using namespace std;



/**
 *
 *
 **/
static int
conv_fun(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *data)
{
	int count;
	struct pam_response *r;

	r = (struct pam_response *)calloc(num_msg, sizeof(pam_response));
	if (!r)
		return PAM_BUF_ERR;

	for(count = 0; count < num_msg; ++count) {
		switch(msg[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			// Nothing special to do here
			break;
		case PAM_ERROR_MSG:
			syslog(LOG_ERR, "webgui: %s\n", msg[count]->msg);
			break;
		case PAM_TEXT_INFO:
			syslog(LOG_INFO, "webgui: %s\n", msg[count]->msg);
			break;
		default:
			syslog(LOG_ERR, "webgui: Erroneous Conversation (%d)\n",
			       msg[count]->msg_style);
			break;
		}

		r[count].resp_retcode = 0;
		r[count].resp = x_strdup((char *)data);
	}

	*resp = r;
	return PAM_SUCCESS;
}


/**
 *
 *
 **/
static void
base64Decode(unsigned char* pIn, int inLen, unsigned char* pOut,
             int& outLen)
{
	// create a memory buffer containing base64 encoded data
	BIO* bmem = BIO_new_mem_buf((void*)pIn, inLen);

	// push a Base64 filter so that reading from buffer decodes it
	BIO *bioCmd = BIO_new(BIO_f_base64());
	// we don't want newlines
	BIO_set_flags(bioCmd, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_push(bioCmd, bmem);

	int finalLen = BIO_read(bmem, (void*)pOut, outLen);
	BIO_free_all(bmem);
	outLen = finalLen;
}


/**
 *
 *
 **/
bool
AuthBasic::handle(const string &auth)
{
	if (auth.size() < Rest::AUTH_BASIC.size()) {
		return false;
	} else {
		return (auth.compare(0, Rest::AUTH_BASIC.size(), Rest::AUTH_BASIC) == 0);
	}
}


/**
 *
 *
 **/
bool
AuthBasic::authorized(const string &val, Session &session)
{
	if (val.size() < (Rest::AUTH_BASIC.size()+1)) {
		return false;
	}
	//now split off "basic"
	string auth = val.substr(Rest::AUTH_BASIC.size()+1);
	if (auth.empty() == true) {
		session.vyatta_debug("AAB");
		return false;
	}
	unsigned char out[1025];
	int len = 1024;
	base64Decode((unsigned char*)auth.c_str(),auth.size(),(unsigned char*)&out,len);

	string str_out = string((char*)out);
	size_t pos = str_out.find(":");
	if (pos == string::npos) {
		return false;
	}
	string username = str_out.substr(0,pos);
	string password = str_out.substr(pos+1,len-pos-1);

	session._user = username;

	string pam_service = "login";
	string path = session._request.get(Rest::HTTP_REQ_URI);
	
	if (path.find(Rest::SERVICE_REQ_ROOT) == 0
		|| session._request.get(Rest::HTTP_REQ_PRAGMA).find(Rest::PRAGMA_SERVICE_USER) != string::npos) {
		pam_service = "vyatta-service-users.conf";
		session._service_user = true;
		session._access_level = Session::k_VYATTASERVICE_USER;
	}

	//debug (never log the password or the decoded credentials)
	dsyslog(_debug, "%s: auth2a: user %s", __func__, username.c_str());

	//now have user and pw--need to  figure out what to do with this...

	struct passwd *pw = NULL;
	gid_t primary_g_gr_gid = 0;
	if (!session._service_user) {
		//for now check if this is a member of the vyattacfg group-- auth will really happen at the server level once configured...

		pw = getpwnam(username.c_str());
		if (!pw) {
			session.vyatta_debug("AAC");
			dsyslog(_debug, "%s: auth3", __func__);
			return false;
		}

		//debug
		dsyslog(_debug, "%s: auth4", __func__);

		primary_g_gr_gid = pw->pw_gid;

		/* Retrieve group list */
		int ngroups = 10;
		gid_t groups[10];
		if (getgrouplist(username.c_str(), pw->pw_gid, groups, &ngroups) == -1) {
			session.vyatta_debug("AAF0");
			return false;
		}

		for (int j = 0; j < ngroups; j++) {
			struct group *gr = getgrgid(groups[j]);
			if (gr != NULL) {
				if (strcmp(gr->gr_name,"vyattacfg") == 0) {
					session._access_level = Session::k_VYATTACFG;
					primary_g_gr_gid = gr->gr_gid;
					if (_debug) {
						session._response.append(Rest::HTTP_RESP_DEBUG,"AAF0");
					}
				}
			}
		}

		if (setgroups(ngroups,groups) != 0) {
			session.vyatta_debug("AAF5");
			return false;
		}

		dsyslog(_debug, "%s: !auth6b:%d", __func__, primary_g_gr_gid);
	}

	char *passwd = strdup(password.c_str());
	if (!passwd) {
		return false;
	}
	pam_conv conv = { conv_fun, passwd };
	dsyslog(_debug, "%s: auth8", __func__);

	pam_handle_t *pam = NULL;
	int result = pam_start(pam_service.c_str(), username.c_str(), &conv, &pam);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_start failed: result=%d", __func__, result);
		session.vyatta_debug("AAG");
		free(passwd);
		return false;
	}

	dsyslog(_debug, "%s: auth9: pam=%p", __func__, pam);

	result = pam_authenticate(pam, 0);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: failed on pam_authenticate for: %s, %d", __func__,
			username.c_str(), result);
		session.vyatta_debug("AAH");
		free(passwd);
		return false;
	}

	result = pam_acct_mgmt(pam, 0);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_acct_mgmt failed: result=%d", __func__, result);
		session.vyatta_debug("AAI");
		free(passwd);
		return false;
	}

	result = pam_end(pam, result);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_end failed: result=%d", __func__, result);
		session.vyatta_debug("AAJ");
		free(passwd);
		return false;
	}
	free(passwd);

	dsyslog(_debug, "%s: auth10", __func__);

	if (!session._service_user) {
		uid_t pw_uid = pw->pw_uid;
		if (audit_setloginuid(pw_uid) < 0) {
			syslog(LOG_ERR, "Failed to set loginuid\n");
			return false;
		}
		if (setegid(primary_g_gr_gid) != 0) {
			dsyslog(_debug, "%s: auth11", __func__);
			session.vyatta_debug("AAK");
			return false;
		}
		dsyslog(_debug, "%s: auth6c %d ", __func__, pw_uid);
		if (seteuid(pw_uid) != 0) {
			dsyslog(_debug, "%s: auth12", __func__);
			session.vyatta_debug("AAL");
			return false;
		}
	}
	dsyslog(_debug, "%s: auth13", __func__);

	// TODO: Want to set back uid and gid on failure...

	session._auth_type = Rest::AUTH_TYPE_BASIC;

	return true;
}


