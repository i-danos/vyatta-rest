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

#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <errno.h>
#include "authbase.hh"
#include "authbasic.hh"
#include "authsession.hh"
#include "authenticate.hh"

using namespace std;


/**
 *
 *
 **/
Authenticate::Authenticate(bool debug) : _debug(debug)
{
	_auth_coll.push_back(new AuthBasic(debug));
	_auth_coll.push_back(new AuthSession(debug));
}


/**
 *
 *
 **/
bool
Authenticate::validate(Session &session)
{
	string auth = session._request.get(Rest::HTTP_REQ_AUTHORIZATION);
        string cookie = session._request.get(Rest::HTTP_REQ_COOKIE);
        if (auth.empty() == true && cookie.empty() == true) {

		session.vyatta_debug("AAA");
		return false;
	}
       if (auth.empty() == true)
         auth = cookie;


	//debug (never include the Authorization header or the cookie: a Basic
	//header is base64 of user:password and the cookie is a session key)
	session.vyatta_debug("AAAA");

	/*
	 * here is where we'll identify the authentication scheme
	 *
	 */
	AuthIter iter = _auth_coll.begin();
	while (iter != _auth_coll.end()) {
		if ((*iter)->handle(auth)) {
			return ((*iter)->authorized(auth,session));
		}
		++iter;
	}
	return false;
}
