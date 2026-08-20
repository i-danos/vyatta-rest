/**
 * Module: common.cc
 * Description: common definitions related to the webgui2 project
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <errno.h>
#include "common.hh"
#include "debug.h"

using namespace std;

string Rest::REST_SERVER_VERSION = "0.3";

string Rest::JSON_INPUT = "/tmp/json_input";
unsigned long Rest::MAX_BODY_SIZE = 33554432;
unsigned long Rest::PROC_KEY_LENGTH = 16;
string Rest::CONF_REQ_ROOT = "/rest/conf";
string Rest::OP_REQ_ROOT = "/rest/op";
string Rest::APP_REQ_ROOT = "/rest/app";
string Rest::PERM_REQ_ROOT = "/rest/perm";
string Rest::SERVICE_REQ_ROOT = "/rest/service";

const string Rest::AUTH_BASIC = "Basic";
const string Rest::AUTH_VYATTA_SESSION = "Vyatta-Session";
const string Rest::AUTH_VYATTA_PATH_LOC = "vyatta2_path_loc";

const string Rest::PRAGMA_NO_VYATTA_SESSION_UPDATE = "no-vyatta-session-update";
const string Rest::PRAGMA_SERVICE_USER = "vyatta-service-user";

//conf mode stuff
const string Rest::CONFIG_TMP_DIR = "/tmp/";
const string Rest::LOCAL_CHANGES_ONLY = "/rw/";
const string Rest::LOCAL_CONFIG_DIR = "/u/";

//op mode stuff
const string Rest::OP_COMMAND_DIR = "/opt/vyatta/share/vyatta-op/templates";
const string Rest::CONF_COMMAND_DIR = "/opt/vyatta/share/vyatta-cfg/templates";
const string Rest::SERVICE_COMMAND_DIR = "/opt/vyatta/share/vyatta-service/templates";
const string Rest::CHUNKER_RESP_TOK_DIR = "/opt/vyatta/tmp/webgui2/";
const string Rest::CHUNKER_RESP_TOK_BASE = "multi_";
const string Rest::CHUNKER_RESP_PID = "/tmp"; //"/opt/vyatta/var/run";
const string Rest::CHUNKER_SOCKET = "/tmp/browser_pager2";
const unsigned long Rest::CHUNKER_MAX_WAIT_TIME = 2; //seconds
const unsigned long Rest::CHUNKER_READ_SIZE = 98304;
const string Rest::CHUNKER_COMMAND_FORMAT = "<vyatta><command><token>%s</token><statement>%s</statement><user>%s</user></command></vyatta>\0\0";
const string Rest::CHUNKER_PROCESS_FORMAT = "<vyatta><process><token>%s</token><user>%s</user></process></vyatta>\0\0";
const string Rest::CHUNKER_DETAILS_FORMAT = "<vyatta><details><token>%s</token><user>%s</user></details></vyatta>\0\0";
const string Rest::CHUNKER_NEXT_FORMAT = "<vyatta><next><token>%s</token><user>%s</user></next></vyatta>\0\0";
const string Rest::CHUNKER_DELETE_FORMAT = "<vyatta><delete><token>%s</token><user>%s</user></delete></vyatta>\0\0";
const string Rest::VYATTA_MODIFY_FILE = Rest::CONFIG_TMP_DIR + ".vyattamodify_";


const char* Rest::g_type_str[] = {"none", "text", "ipv4", "ipv4net", "ipv6", "ipv6net", "u32", "bool", "macaddr"};


/**
 *
 **/
Timer::Timer(string id) : _id(id)
{
	// TODO: gtod is susceptible to NTP time changes
	gettimeofday(&_start_time,NULL);
}

Timer::~Timer()
{
	struct timeval end_time;
	// TODO: gtod is susceptible to NTP time changes
	gettimeofday(&end_time,NULL);

	unsigned long usecs = abs(_start_time.tv_usec - end_time.tv_usec);
	unsigned long secs = end_time.tv_sec - _start_time.tv_sec;
	if (_start_time.tv_usec >= end_time.tv_usec) {
		secs = secs - 1;
		usecs = 1000000 - usecs;
	}

	dsyslog(true, "%s: timer(%s): elapsed sec %lu, usec %lu", __func__, _id.c_str(),
		secs, usecs);
}


string
Rest::ulltostring(unsigned long long in)
{
	stringstream ss;
	ss << in;
	return ss.str();
}

/**
 * \brief Execute a command capturing the output
 *
 * \param cmd Command to execute
 * \param stdout Stores command output
 * \param read Flag indicating direction of stream (r or w)
 **/
int
Rest::execute(std::string &cmd, std::string &stdout, bool read)
{
	int err = 0;

	string dir = "w";
	if (read == true) {
		dir = "r";
	}
	FILE *f = popen(cmd.c_str(), dir.c_str());
	if (f) {
		if (read == true) {
			fflush(f);
			char *buf = NULL;
			size_t len = 0;
			ssize_t read_len = 0;
			while ((read_len = getline(&buf, &len, f)) != -1) {
				stdout += string(buf) + " ";
			}

			if (buf) {
				free(buf);
			}
		}
		err = pclose(f);
		if (WIFEXITED(err)) {
			err = WEXITSTATUS(err);
		}
	}
	/*
	char b[10000];
	sprintf(b,"echo '%s' >> /tmp/apperr0",stdout.c_str());
	system(b);
	sprintf(b,"echo %d >> /tmp/apperr0",err);
	system(b);
	*/


	return err;
}


/**
 * \brief Replace all instances of victim with replacement
 *
 * \param source Original string
 * \param victim Substring to replace
 * \param replacement What to replace victim with
 **/
std::string
Rest::mass_replace(const std::string &source, const std::string &victim, const
                   std::string &replacement)
{
	std::string::size_type jump = replacement.length();
	std::string answer = source;
	std::string::size_type j = 0;
	std::string::size_type offset= 0;
	while ((j = answer.find(victim, j+offset)) != std::string::npos ) {
		offset = jump;
		answer.replace(j, victim.length(), replacement);
	}
	return answer;
}



/**
 *
 **/
std::string
Rest::trim(const std::string &src)
{
	string str(src);
	size_t startpos = str.find_first_not_of(" \t");
	size_t endpos = str.find_last_not_of(" \t");
	if(( string::npos == startpos ) || ( string::npos == endpos)) {
		str = "";
	} else {
		str = str.substr( startpos, endpos-startpos+1 );
	}
	return str;
}



/**
 * Token is of the form: multi_%rand%_%chunk%
 **/
std::string
Rest::generate_token()
{
	string ret = string("");;
	//if tok is empty then generate a new one
	unsigned long val;
	char buf[80];

	int ct = 5; //will try 5 times in case of failure.
	FILE *fp = NULL;
	while (fp == NULL && ct > 0) {
		fp = fopen("/dev/urandom", "r");
		if (fp) {
			char *ptr = (char*)&val;
			*ptr = fgetc(fp);
			if (*ptr == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+1) = fgetc(fp);
			if (*(ptr+1) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+2) = fgetc(fp);
			if (*(ptr+2) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+3) = fgetc(fp);
			if (*(ptr+3) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			unsigned long id1 = unsigned(val);

			*ptr = fgetc(fp);
			if (*ptr == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+1) = fgetc(fp);
			if (*(ptr+1) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+2) = fgetc(fp);
			if (*(ptr+2) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			*(ptr+3) = fgetc(fp);
			if (*(ptr+3) == EOF) {
				fclose(fp);
				fp = NULL;
				continue;
			}
			unsigned long id2 = unsigned(val);

			fclose(fp);

			//need to pad out src_ip to fill up 10 characters
			sprintf(buf, "%.8lX%.8lX",id1,id2);
			return string(buf);
		} else {
			//      printf("failure to get filehandle\n");
		}
		--ct;
		usleep(20 * 1000); //20 millisleep between tries
	}
	//  printf("failure to get random value: %d\n",ct);
	return ret;
}

/**
 *
 **/
int
Rest::mkdir_p(const char *path)
{
	if (mkdir(path, 0777) == 0)
		return 0;

	if (errno != ENOENT)
		return -1;

	char *tmp = strdup(path);
	if (tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	char *slash = strrchr(tmp, '/');
	if (slash == NULL) {
		free(tmp);
		return -1;
	}
	*slash = '\0';

	/* recurse to make missing piece of path */
	int ret = mkdir_p(tmp);
	if (ret == 0)
		ret = mkdir(path, 0777);

	free(tmp);
	return ret;
}


/**
 * \brief Create a file containing user assigned description
 *
 * One set of REST commands allows the user to assign a description
 * field to a configuration tree and a tag. This function creates the
 * file containing that description.
 *
 * \param id Config session id (?)
 * \param user User associated with description
 * \param description User supplied description
 **/
bool
Rest::create_conf_modify_file(const string &id, const string &user, const string &description)
{
	string file = Rest::VYATTA_MODIFY_FILE + id;
	FILE *fp = fopen(file.c_str(), "w");
	if (!fp) {
		return false;
	}

	string str = user + "/" + description;

	if (fputs(str.c_str(), fp) == EOF) {
		fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}

/**
 * \brief Read user assigned description
 *
 * \param id Config session id (?)
 * \param user User associated with description
 * \param description User supplied description
 **/
bool
Rest::read_conf_modify_file(const string &id, string &user, string &description)
{
	string file = Rest::VYATTA_MODIFY_FILE + id;
	FILE *fp = fopen(file.c_str(), "r");
	if (!fp) {
		return false;
	}

	char buf[Rest::CHUNKER_READ_SIZE];
	if (fgets(buf,Rest::CHUNKER_READ_SIZE,fp) != NULL) {
		string str(buf);
		size_t pos = str.find("/");
		if (pos == string::npos) {
			fclose(fp);
			return false;
		}
		user = str.substr(0,pos);
		description = str.substr(pos+1);
	}
	fclose(fp);
	return true;
}

/**
 * \brief Get id associated with tag
 *
 * \param tag Tag to look for
 * \param user User that assigned tag
 * \param id Id of tag (?)
 **/
bool
Rest::read_conf_modify_file_from_tag(const std::string &tag, std::string &user, std::string &id)
{
	struct dirent *dirp;
	DIR *dp;
	if ((dp = opendir(Rest::CONFIG_TMP_DIR.c_str())) == NULL) {
		return false;
	}

	if (dp != NULL) {
		while ((dirp = readdir(dp)) != NULL) {
			string conf_file = string(dirp->d_name);
			if (conf_file.length() < 22) {
				continue;
			}

			string f_tag, f_user;
			string f_id = string(dirp->d_name).substr(14);
			read_conf_modify_file(f_id,f_user,f_tag);
			if (f_tag.empty() == false && tag == f_tag && f_user == user) {
				id = f_id;
				closedir(dp);
				return true;
			}
		}
	}
	closedir(dp);
	return false;
}

/**
 * \brief Convert REST command to CLI command
 *
 * \param curl_handle curl handle
 * \param in_cmd Rest command to execute
 **/
std::string
Rest::translate_rest_to_cli(CURL *curl_handle,const std::string &in_cmd)
{
	string cmd;
	int ct = 0;
	size_t cur_pos,old_pos = 0;
	cmd = string("");
	while ((cur_pos = in_cmd.find("/",old_pos+1)) != string::npos) {
		string token = in_cmd.substr(old_pos+1,cur_pos - (old_pos+1));
		int len;
		token = string(curl_easy_unescape(curl_handle,token.c_str(),token.length(),&len));
		if (ct == 0) {
			cmd = in_cmd.substr(0,cur_pos);
		} else {
			//handle three cases here
			// 1. value is already enclosed with single quotes
			// 2. value is already enclosed with double quotes
			// 3. all else
			if (token[0] == '\'' && token[token.length()-1] == '\'') {
				cmd += " " + token;
			} else if (token[0] == '"' && token[token.length()-1] == '"') {
				cmd += " '" + token.substr(1,token.length()-2) + "'";
			} else {
				cmd += " '" + token + "'";
			}
		}
		old_pos = cur_pos;
		ct++;
	}
	if (ct > 0) {
		string t = in_cmd.substr(old_pos+1);
		int len;
		t = string(curl_easy_unescape(curl_handle,t.c_str(),t.length(),&len));
		//doesn't work because these need to look for unescaped values...
		if (t[0] == '\'' && t[t.length()-1] == '\'') {
			cmd += " " + t;
		} else if (t[0] == '"' && t[t.length()-1] == '"') {
			cmd += " '" + t.substr(1,t.length()-2) + "'";
		} else {
			cmd += " '" + t + "'";
		}
	}
	return cmd;
}
