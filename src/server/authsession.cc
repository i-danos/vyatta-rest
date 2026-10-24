/**
 * Module: authsession.cc
 * Description: Authentication support
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2009-2013 Vyatta, Inc.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 **/

#include <libaudit.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <errno.h>
#include "rl_str_proc.hh"
#include "common.hh"
#include "authbase.hh"
#include "authsession.hh"
#include "debug.h"

using namespace std;

const unsigned long Lock::_retry_lock_interval = 50; //50 milliseconds
const unsigned long Lock::_retry_lock_count = 5; //5 times

const string AuthSession::_session_file = "/var/run/gui/session";
const unsigned long AuthSession::_session_timeout = 30 * 60; //30 minutes (in seconds)

/**
 *
 *
 **/
Lock::Lock(const string &file) :
	_file(file),
	_fp(NULL),
	_fp_tmp(NULL),
	_lck_fd(-1),
	_status(false)
{
	string tmp_file = _file + "_tmp";
	string lck_file = _file + ".lck";

	_mask = umask(0111);

	//acquire lock
	unsigned long ct = 0;
	while (_lck_fd < 0 && ct < _retry_lock_count) {
		_lck_fd=open(lck_file.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRWXU);
		if (_lck_fd<0 && errno==EEXIST) {
			// the file already exist; another process is
			// holding the lock
			usleep(_retry_lock_interval * 1000);
		} else if (_lck_fd < 0) {
			cerr << "locking failed" << endl;
		} else {
			break; //done
		}
		++ct;
	}
	_fp = fopen(_file.c_str(), "r+");
	_fp_tmp = fopen(tmp_file.c_str(), "w");
	if (_fp != NULL && _fp_tmp != NULL && ct != _retry_lock_count) {
		_status = true;
	}
}



/**
 *
 *
 **/
Lock::~Lock()
{
	string tmp_file = _file + "_tmp";
	string lck_file = _file + ".lck";

	umask(_mask);

	if (_fp_tmp != NULL) {
		fclose(_fp_tmp);
	}
	if (_fp != NULL) {
		fclose(_fp);
	}
	rename(tmp_file.c_str(),_file.c_str());

	if (_lck_fd > -1) {
		close(_lck_fd);
	}
	unlink(lck_file.c_str());
}


/**
 *
 *
 **/
AuthSession::AuthSession(bool debug) : AuthBase(debug)
{
	//clear on startup....
	unlink(_session_file.c_str());
	string tmp_file = _session_file + "_tmp";
	string lck_file = _session_file + ".lck";

	unlink(tmp_file.c_str());
	unlink(lck_file.c_str());
}

/**
 *
 *
 **/
bool
AuthSession::handle(const string &auth)
{
        if (auth.find(Rest::AUTH_VYATTA_PATH_LOC) != string::npos)
                return true;

	if (auth.size() < Rest::AUTH_VYATTA_SESSION.size()) {
		return false;
	} else {
		return (auth.compare(0, Rest::AUTH_VYATTA_SESSION.size(), Rest::AUTH_VYATTA_SESSION) == 0);
	}
}


/**
 *
 *
 **/
bool
AuthSession::authorized(const string &val, Session &session)
{
	/*
	  Need to go through and check session against registered session.
	  Need to validate that session is still valid (i.e. hasn't time expired),
	  and need to associate username to session within session object.

	  Note, does not create session here--not sure where this occurs, possibly via app?
	  Creation should not be supported through authorization though.
	*/
	int ngroups = 10;
	gid_t groups[10];

        if (val.size() < (Rest::AUTH_VYATTA_SESSION.size()+1)
            || val.size() < (Rest::AUTH_VYATTA_PATH_LOC.length()+1)) {
		return false;
	}

        string key = "";
        size_t key_pos = val.find(Rest::AUTH_VYATTA_PATH_LOC);
        if (key_pos != string::npos) {
           // Magic numbers:
           // +1 for the '=' charachter in vyatta2_path_loc=
           // The session cookie consists of 16 characters.
           key = val.substr(key_pos + Rest::AUTH_VYATTA_PATH_LOC.length() + 1, 16);
        }

	//now split off "vyatta-session"
        string auth = "";
        size_t auth_pos = val.find(Rest::AUTH_VYATTA_SESSION);
        if (auth_pos != string::npos) {
           // Magic numbers:
           // +1 for the space charachter in "Vyatta-Session FFFFFFFF..."
           // The session cookie consists of 16 characters.
           auth = val.substr(auth_pos + Rest::AUTH_VYATTA_SESSION.length() + 1, 16);
        }
        
        if (auth.empty() == true && key.empty() == true) {
	 	if (_debug) {
			session._response.append(Rest::HTTP_RESP_DEBUG,"AABs1");
		}
		return false;
	}

        if (auth.empty() == true)
          auth = key;

	//lock file

	//parse file

	//unlock file
	Lock lock(_session_file);

	if (lock.status() == false) {
		syslog(LOG_ERR,"Failed to access vyatta session information");
		return false;
	}

	if (_debug) {
		session._response.append(Rest::HTTP_RESP_DEBUG,"AABs3");
	}

	timeval cur_time;
	gettimeofday(&cur_time,NULL);

	bool found(false);
	char buf[1025];
	struct passwd *pw = NULL;
	//now let's do the diry work and compare the session key
	FILE *fp = lock.get_fp();
	FILE *fp_tmp = lock.get_fp_tmp();
	if (fp != NULL && fp_tmp != NULL) {

		if (_debug) {
			session._response.append(Rest::HTTP_RESP_DEBUG,"AABs4");
		}

		while (fgets(buf,1024,fp) != NULL) {
			StrProc s(buf,",");
			string sess_access_level = s.get(4);
			//let's continue and check timeout

			if (_debug) {
				session._response.append(Rest::HTTP_RESP_DEBUG,"AABs5");
			}

			//debug (never log the session record or the presented session key)
			dsyslog(_debug, "%s: authsession(1): checking session record", __func__);

			unsigned long session_time = strtoul(s.get(2).c_str(),NULL,10);

			dsyslog(_debug, "%s: authsession(2): %ld,%ld,%ld", __func__,
				session_time,_session_timeout,(unsigned long)cur_time.tv_sec);

			if (_debug) {
				session._response.append(Rest::HTTP_RESP_DEBUG,"AABs6");
			}

			if ((session_time + _session_timeout) > (unsigned long)cur_time.tv_sec) {
				if (_debug) {
					session._response.append(Rest::HTTP_RESP_DEBUG,"AABs7");
				}

				dsyslog(_debug, "%s: authsession(3): record is within the timeout", __func__);
				if (s.get(0) == auth) {
					//this is our session
					if (_debug) {
						session._response.append(Rest::HTTP_RESP_DEBUG,"AABs8");
					}
					session._user = s.get(1); //set user
					session._session_key = s.get(0); //set session id, todo: encapsulate this...

					if (sess_access_level == "service-user") {
						session._access_level = Session::k_VYATTASERVICE_USER;
						session._service_user = true;
					}

					if (!session._service_user) {
						pw = getpwnam(s.get(1).c_str());
						if (!pw) {
							dsyslog(_debug, "%s: auth3", __func__);
							if (_debug) {
								session._response.append(Rest::HTTP_RESP_DEBUG,"AAC");
							}
							return false;
						}

						/* Retrieve group list */
						if (getgrouplist(session._user.c_str(), pw->pw_gid, groups, &ngroups) == -1) {
							if (_debug) {
								session._response.append(Rest::HTTP_RESP_DEBUG,"AAF0");
							}
							return false;
						}

						for (int j = 0; j < ngroups; j++) {
							struct group *gr = getgrgid(groups[j]);
							if (gr != NULL) {
								if (strcmp(gr->gr_name,"vyattacfg") == 0) {
									session._access_level = Session::k_VYATTACFG;
									if (_debug) {
										session._response.append(Rest::HTTP_RESP_DEBUG,"AAF0");
									}
								}
							}
						}

					}

					char updated_sess[1024];
					memset(updated_sess,'\0',1024);
					if (session._request.get(Rest::HTTP_REQ_PRAGMA).find(Rest::PRAGMA_NO_VYATTA_SESSION_UPDATE) != string::npos) {
						sprintf(updated_sess,"%s,%s,%ld,%s,%s\n",s.get(0).c_str(),s.get(1).c_str(),session_time,s.get(3).c_str(), sess_access_level.c_str());
					} else {
						sprintf(updated_sess,"%s,%s,%ld,%s,%s\n",s.get(0).c_str(),s.get(1).c_str(),cur_time.tv_sec,s.get(3).c_str(), sess_access_level.c_str());
					}

					if (fputs(updated_sess,fp_tmp) < 0) {
						syslog(LOG_ERR, "Error on updating session file");
						continue;
					}

					session._auth_type = Rest::AUTH_TYPE_VYATTA_SESSION;
					found = true;
				} else {
					if (fputs(buf,fp_tmp) < 0) {
						syslog(LOG_ERR, "Error on updating session file");
						break;
					}
				}
			}
		}
	}

	if (found && !session._service_user) {
		if (audit_setloginuid(pw->pw_uid) < 0) {
			syslog(LOG_ERR, "Failed to set loginuid\n");
			return false;
		}

		if (setgroups(ngroups,groups) != 0) {
			if (_debug) {
				session._response.append(Rest::HTTP_RESP_DEBUG,"AAF5");
			}
			return false;
		}

		if (setegid(pw->pw_gid) != 0) {
			if (_debug) {
				session._response.append(Rest::HTTP_RESP_DEBUG,"AAF6");
			}
			return false; //error on setting permisssions
		}

		if (seteuid(pw->pw_uid) != 0) {
			dsyslog(_debug, "%s: auth6ca", __func__);
			if (_debug) {
				session._response.append(Rest::HTTP_RESP_DEBUG,"AAF7");
			}
			return false; //error on setting permisssions
		}
	}

	return found;
}


