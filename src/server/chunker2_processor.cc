/**
 * Module: chunker2_processor.cc
 * Description: Background processor for single process
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2009-2013 Vyatta, Inc.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 **/

#include <libaudit.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstring>
#include <pwd.h>
#include <strings.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <grp.h>
#include "common.hh"
#include "http.hh"
#include "chunker2_processor.hh"
#include <vector>

using namespace std;

/**
 *
 **/
bool
ChunkerProcessor::start_new(string token, const string &cmd, const string &user)
{
	if (_debug) {
		cout << "ChunkerProcessor::start_new(): starting new processor. cmd: " << cmd << ", user: " << user << endl;
	}

	if (cmd.empty() == true || token.empty() == true || user.empty() == true) {
		return false;
	}

	struct sigaction sa;
	sigaction(SIGCHLD, NULL, &sa);
	sa.sa_flags |= SA_NOCLDWAIT;//(since POSIX.1-2001 and Linux 2.6 and later)
	sigaction(SIGCHLD, &sa, NULL);

	if (fork() != 0) {
		//parent
		return true;
	}

	//should detach child process at this point

	umask(0);
	setsid();

	int cp[2]; /* Child to parent pipe */

	if( pipe(cp) < 0) {
		perror("Can't make pipe");
		exit(1);
	}


	//set up to run as user id...

	//move this up the timeline in the future, but this is where we will initially set the uid/gid
	//retreive username, then use getpwnam() from here to populate below
	struct passwd *pw;
	pw = getpwnam(user.c_str());
	if (pw == NULL) {
		return false;
	}

	pid_t pid = fork();

	if (pid == 0) {
		//child
		if (audit_setloginuid(pw->pw_uid) < 0) {
			perror("setloginuid");
			exit(1);
		}

		/* Retrieve group list */
		int ngroups = 10;
		gid_t groups[10];
		if (getgrouplist(user.c_str(), pw->pw_gid, groups, &ngroups) == -1) {
			return false;
		}

		if (setgroups(ngroups,groups) != 0) {
			syslog(LOG_DEBUG,"grouperror: %d",errno);
			return false;
		}
		if (setgid(pw->pw_gid) != 0) {
			return false;
		}
		if (setuid(pw->pw_uid) != 0) {
			return false;
		}

		//now we are ready to do some real work....

		writer(token,cmd,cp,user);
		exit(0);
	} else {
		//parent
		reader(token,cp);

		//now wait on child to kick the bucket
		wait(NULL);
		exit(0);
	}
	return true;
}

/**
 *
 **/
void
ChunkerProcessor::writer(string token, const string &cmd,int (&cp)[2], string user)
{
	//use child pid to allow cleanup of parent
	if (_pid_path.empty() == false) {
		_pid_path += "/" + token;
		pid_output(_pid_path.c_str());
	}
	/* Child. */
	close(1); /* Close current stdout. */
	dup2(cp[1],1); /* Make stdout go to write end of pipe. */
	dup2(cp[1],2); /* Make stderr go to write end of pipe. */
	close(0); /* Close current stdin. */
	close(cp[0]);

	string opmodecmd = cmd;
	string userenv = "EFFECTIVE_USER="+user;
	string processclientenv = "VYATTA_PROCESS_CLIENT=gui2_rest";
	vector <string> opcmdarr;
	tokenizeOpCmd(opmodecmd, opcmdarr);

	// String literals, not temporary std::strings: each string(...) below
	// used to be destroyed at the end of its own statement, leaving c_str()
	// dangling before execve ever saw it. Literals have static storage, so
	// the pointers stay valid.
	char *cmdarr[4];
	cmdarr[0] = (char *)"/opt/vyatta/bin/opc";
	cmdarr[1] = (char *)"-op";
	cmdarr[2] = (char *)"run-from-env";
	cmdarr[3] = NULL;

	// Create json args to pass in via environment
	// format is OPC_ARGS={"args": ["arg1", "args2", "argn"]}
	JSON args;
	for (vector <string>::size_type i = 0; i<opcmdarr.size(); i++) {
		args.add_array("args", opcmdarr[i], false);
	}
	string opcargs;
	args.serialize(opcargs);
	opcargs = "OPC_ARGS=" + opcargs;

	char *envarr[] = {
		(char*)userenv.c_str(),
		(char*)processclientenv.c_str(),
		(char*)opcargs.c_str(),
		NULL
	};
	int err = execve("/opt/vyatta/bin/opc", cmdarr, envarr);
	close(cp[1]);
	if (err == -1) {
		syslog(LOG_ERR, "ERROR RECEIVED FROM EXECVP(1): %d, %d",err, errno);
	}
}

void
ChunkerProcessor::tokenizeOpCmd(string &opmodecmd, vector<string> &opcmdarr)
{
	size_t seploc = 0;
	size_t strloc = 0;
	size_t quote_open = 0;
	size_t quote_close = 0;
	string substr;
	while(true) {
		seploc = opmodecmd.find(" ", strloc);
		if (seploc == string::npos) {
			seploc = opmodecmd.size();
			quote_open = opmodecmd.find('\'', strloc);
			if (quote_open == strloc) {
				quote_close = opmodecmd.find('\'', quote_open+1);
				substr = opmodecmd.substr((quote_open+1), (quote_close-quote_open-1));
			} else {
				substr = opmodecmd.substr(strloc, (seploc-strloc+1));
			}
			if (substr != "" && substr != "''") {
				opcmdarr.push_back(substr.c_str());
			}
			break;
		}
		quote_open = opmodecmd.find('\'', strloc);
		if (quote_open == strloc) {
			quote_close = opmodecmd.find('\'', quote_open+1);
			substr = opmodecmd.substr((quote_open+1), (quote_close-quote_open-1));
			opcmdarr.push_back(substr.c_str());
			strloc = quote_close+1;
		} else {
			substr = opmodecmd.substr(strloc, (seploc-strloc));
			if (substr != "") {
				opcmdarr.push_back(substr.c_str());
			}
			strloc = seploc+1;
		}
	}
}
/**
 *
 **/
void
ChunkerProcessor::reader(string token, int (&cp)[2])
{
	/* Parent. */
	/* Close what we don't need. */
	char buf[_chunk_size+1];
	bzero(buf,_chunk_size+1);
	string tmp;

	//  usleep(1000*1000);
	close(cp[1]);
	int ct = 0;
	while ((ct = read(cp[0], &buf, _chunk_size)) > 0) {
		tmp += string(buf);
		tmp = process_chunk(tmp, token);
		bzero(buf,_chunk_size+1);
	}
	process_chunk_end(tmp,token);
	close(cp[0]);
}


/**
 * write out remainder and create bumper
 **/
void
ChunkerProcessor::process_chunk_end(string &str, string &token)
{
	//OK, let's find a natural break and start processing
	size_t pos = str.rfind('\n');
	string chunk;
	if (pos != string::npos) {
		chunk = str.substr(0,pos);
		str = str.substr(pos+1,str.length());
	} else {
		chunk = str;
		str = string("");
	}

	string file = Rest::CHUNKER_RESP_TOK_DIR + Rest::CHUNKER_RESP_TOK_BASE + token;
	FILE *fp = fopen(file.c_str(), "a");
	if (fp) {
		size_t len = chunk.length();
		if (fwrite(chunk.c_str(),1,len,fp) < len)
			syslog(LOG_ERR,"webgui: Error writing out response chunk");
		fclose(fp);
	} else {
		syslog(LOG_ERR,"webgui: Failed to write out response chunk");
	}


	//if we naturally end write out bumper file to common directory...
	file = Rest::CHUNKER_RESP_TOK_DIR + Rest::CHUNKER_RESP_TOK_BASE + token + "_end";
	fp = fopen(file.c_str(), "w");
	if (fp) {
		size_t endlen = 3;
		if (fwrite("end", 1, endlen, fp) < endlen)
			syslog(LOG_ERR,"webgui: Error writing response chunk end");
		fclose(fp);
	}
	return;
}

/**
 *
 **/
string
ChunkerProcessor::process_chunk(string &str, string &token)
{

	//OK, let's find a natural break and start processing
	string file = Rest::CHUNKER_RESP_TOK_DIR + Rest::CHUNKER_RESP_TOK_BASE + token;
	FILE *fp = fopen(file.c_str(), "a");
	if (fp) {
		size_t len = str.length();
		if (fwrite(str.c_str(),1,len,fp) < len)
			syslog(LOG_ERR,"webgui: Failed writing response chunk");
		fclose(fp);
	} else {
		syslog(LOG_ERR,"webgui: Failed to write out response chunk");
	}
	return string("");
}

/**
 *
 **/
void
ChunkerProcessor::parse(char *line, char **argv)
{
	while (*line != '\0') {       /* if not the end of line ....... */
		while (*line == ' ' || *line == '\t' || *line == '\n')
			*line++ = '\0';     /* trim */
		*argv++ = line;          /* save the argument position     */
		while (*line != '\0' && *line != ' ' &&
		        *line != '\t' && *line != '\n')
			line++;             /* skip the argument until ...    */
	}
	*argv = NULL;                 /* mark the end of argument list  */
}


/**
 *
 *below borrowed from quagga library.
 **/
#define PIDFILE_MASK 0644
pid_t
ChunkerProcessor::pid_output (const char *path)
{
	FILE *fp;
	pid_t pid;
	mode_t oldumask;

	//  pid = getpid();
	//switched to pid group!
	pid = getpgrp();

	oldumask = umask(0777 & ~PIDFILE_MASK);
	fp = fopen (path, "w");
	if (fp != NULL) {
		fprintf (fp, "%d\n", (int) pid);
		fclose (fp);
		umask(oldumask);
		return pid;
	}
	/* XXX Why do we continue instead of exiting?  This seems incompatible
	   with the behavior of the fcntl version below. */
	syslog(LOG_ERR,"Can't fopen pid lock file %s, continuing",
	       path);
	umask(oldumask);
	return -1;
}
