/***************************************************************************
 *   Copyright (C) 2012 by Infoscope Hellas. All rights reserved.          *
 *   Authors: Charalampos Serenis,                                         *
 *   serenis@dev.infoscope.gr                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.               *
 ***************************************************************************/

/* Standard C includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OS specific includes */
#include <dlfcn.h>
#include <syslog.h>

/* MySQL specific includes */
#include <mysql/mysql.h>
#include <mysql/my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>

/* Third party includes */
#include <ldap.h>
#include <libconfig.h>

config_t cfg, *cf;
char *CONFIG_LDAP_URI = NULL;
char *CONFIG_CACERT_FILE = NULL;
char *CONFIG_BIND_DN = NULL;
char *CONFIG_BIND_PW = NULL;
char *CONFIG_SEARCH_FILTER = NULL;
char *CONFIG_DN = NULL;
const char *CONFIG_LIBLDAP = NULL;

/* For debug, uncomment */
/* #define	DEBUG	1 */

/* This should be moved to the config file */
#ifdef DEBUG
   int log_level = LOG_DEBUG;
#else
   int log_level = LOG_INFO;
#endif

/* Logging functions */
static void openSysLog(void);
static char* vmkString(const char* format,int *size, va_list ap);
static void log_message(int message_type, const char* message, ...);

/* openLDAP wrapper functions */
static int ldap_initialize_wrapper(LDAP**, char*);
static int ldap_set_option_wrapper(LDAP*,int, const void*);
static int ldap_unbind_ext_wrapper(LDAP*, LDAPControl*[], LDAPControl*[]);
static int ldap_sasl_bind_s_wrapper(LDAP*, const char*, const char*,
    struct berval*, LDAPControl*[], LDAPControl*[], struct berval**);
static struct berval* ber_str2bv_wrapper(const char*, ber_len_t, int,
    struct berval*);
static int ldap_search_s_wrapper(LDAP *, char *, int, char *, char *[], int,
    LDAPMessage **);
static int ldap_msgfree_wrapper(LDAPMessage *);

/* Function pointers to ldap functions typedefs */
typedef int (*ldap_initialize_t)(LDAP**, char*);
typedef int (*ldap_set_option_t)(LDAP*, int, const void*);
typedef int (*ldap_unbind_ext_t)(LDAP*, LDAPControl*[], LDAPControl*[]);
typedef int (*ldap_sasl_bind_s_t)(LDAP*, const char*, const char*,
    struct berval*, LDAPControl*[], LDAPControl*[], struct berval**);
typedef struct berval* (*ber_str2bv_t)(const char*, ber_len_t, int,
    struct berval*);
typedef int (*ldap_search_s_t)(LDAP *, char *, int, char *, char *[], int,
    LDAPMessage **);
typedef int (*ldap_msgfree_t)(LDAPMessage *);

/*
 * Functions pointers to openLDAP functions,
 * used by openLDAP wrapper functions
 */
static ldap_initialize_t ldap_initialize_p;
static ldap_set_option_t ldap_set_option_p;
static ldap_unbind_ext_t ldap_unbind_ext_p;
static ldap_sasl_bind_s_t ldap_sasl_bind_s_p;
static ber_str2bv_t ber_str2bv_p;
static ldap_search_s_t ldap_search_s_p;
static ldap_msgfree_t ldap_msgfree_p;
static LDAPMessage* (*ldap_first_entry_p)(LDAP *, LDAPMessage *);
static LDAPMessage* (*ldap_next_entry_p)(LDAP *, LDAPMessage *);
static char* (*ldap_get_dn_p)(LDAP *, LDAPMessage *);
static char* (*ldap_err2string_p)(int);
static void (*ber_bvfree_p)(struct berval *);
static void (*ldap_memfree_p)(void *);

/* Dynamic openLDAP library handle */
static void* libldapHandle = NULL;

/* Flag to signal if the syslog is open or not */
static int syslog_open = 0;

/* Open syslog for logging */
static void
openSysLog(void)
{

	if (syslog_open)
		return;

	openlog("ateam_mysql_ldap_auth", LOG_PID, LOG_DAEMON);
	syslog_open = 1;
}

/* Log an information message to the system log */
static void
log_message(int message_type, const char* message, ...)
{
	/* va_list struct to load the variable argument list */
	va_list ap;
	char *message_prefix;

	/* Check if the syslog is open */
	if (!syslog_open)
		openSysLog();

	/* See if the message is going to get logged with our setting */
	if (message_type > log_level) {
		/* Below our level, don't do anything */
		return;
	}

	/* Pick the prefix */
	switch ( message_type ) {
	case LOG_DEBUG:
		message_prefix = strdup("debug: ");
		break;
	case LOG_INFO:
		message_prefix = strdup("info: ");
		break;
	case LOG_WARNING:
		message_prefix = strdup("warning: ");
		break;
	case LOG_ERR:
		message_prefix = strdup("error: ");
		break;
	default:
		message_prefix = strdup("unknown: ");
		break;
	}

	/* Validate printf style error format */
	if (message == NULL) {
		/* NULL was supplied. Simply log there was an info! */
		syslog(message_type, "%sunknown message logged\n", message_prefix);
	} else {
		/*
		 * Generate the C string based on the error format and
		 * the va_list
		 */
		char *msg;
		int size = 0;
		do {
			va_start(ap, message);
			msg = vmkString(message, &size, ap);
			va_end(ap);
		} while (msg == NULL && (size != 0));
		/* Check if the error message got generated without a problem */
		if (msg == NULL) {
			/* There was an error generating the info message. */
			/* Simply log the info format. */
			syslog(LOG_INFO,"%sunknown message\n", message_prefix);
		}else{
			/* Log the error message */
			syslog(LOG_INFO,"%s%s\n", message_prefix, msg);
			/* Free the allocated space */
			free(msg);
		}
		free(message_prefix);
	}
}

/* Create a C string using a printf format string and a va_list */
static char*
vmkString(const char* format, int *size, va_list ap)
{

	/* Argument check */
	if (format == NULL) {
		*size = 0;
		return (NULL);
	}

	/* Allocate an initial string twice as long as the format string */
	if ((*size) == 0 )
		*size = 2 * strlen(format);

	/* Check the size, to avoid security problems */
	if ((*size) > (1024)) {
		/* Do not allocate a string larger than 1Kbyte */
		*size = 0;
		return (NULL);
	}

	char *cstring;
	cstring = (char*) malloc((*size) * sizeof(char));
	if (cstring == NULL) {
		log_message(LOG_ERR, "vmkString: cannot allocate memory");
		*size = 0;
		return (NULL);
	}

	/* Pass the format string and the variable argument list to vsnprintf */
	int n = vsnprintf(cstring, *size, format, ap);

	/*
	 * Check if vsnprintf returned successfully
	 * Until glibc 2.0.6 vsnprintf would return -1 when the output was
	 * truncated.
	 */
	if (n > -1 && n < (*size))
		return (cstring);

	if (n > -1) {
		/*
		 * glibc is version 2.1 or greater
		 * set the exact string size
		 */
		*size = n + 1;
	} else {
		/*
		 * old version of glib returns -1
		 * double the size
		 */
		*size= 2 * (*size);
	}

	return (NULL);
}

static int
ldap_search_s_wrapper(LDAP *ld, char *base, int scope, char *filter,
    char *attrs[], int attrsonly, LDAPMessage **res)
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_search_s(ld, base, scope, filter, attrs,
	    attrsonly, res));
#else
	return ((*ldap_search_s_p)(ld, base, scope, filter, attrs,
	    attrsonly, res));
#endif
}

static int
ldap_msgfree_wrapper(LDAPMessage *msg)
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_msgfree(msg));
#else
	return ((*ldap_msgfree_p)(msg));
#endif
}

static int
ldap_initialize_wrapper(LDAP** ldp, char *uri)
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_initialize(ldp, uri));
#else
	return ((*ldap_initialize_p)(ldp, uri));
#endif
}

static int
ldap_set_option_wrapper(LDAP *ld, int option, const void *invalue)
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_set_option(ld, option, invalue));
#else
	return ((*ldap_set_option_p)(ld, option, invalue));
#endif
}

static int
ldap_unbind_ext_wrapper(LDAP *ld, LDAPControl *sctrls[],
    LDAPControl *cctrls[])
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_unbind_ext(ld, sctrls, cctrls));
#else
	return ((*ldap_unbind_ext_p)(ld, sctrls, cctrls));
#endif
}

static int
ldap_sasl_bind_s_wrapper(LDAP *ld, const char *dn,
    const char *mechanism, struct berval *cred, LDAPControl *sctrls[],
    LDAPControl *cctrls[], struct berval **servercredp)
{

#ifdef AUTH_LDAP_TEST_API
	return (ldap_sasl_bind_s(ld, dn, mechanism, cred, sctrls, cctrls,
	    servercredp));
#else
	return ((*ldap_sasl_bind_s_p)(ld, dn, mechanism, cred, sctrls, cctrls,
	    servercredp));
#endif
}

static struct berval*
ber_str2bv_wrapper( const char* str, ber_len_t len,
    int dup, struct berval* bv)
{

#ifdef AUTH_LDAP_TEST_API
	return (ber_str2bv(str, len, dup, bv));
#else
	return ((*ber_str2bv_p)(str, len, dup, bv));
#endif
}

/*
 * Server plugin
 */
static int
ldap_auth_server(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *myInfo)
{
	unsigned char *password;
	int pkt_len;

	/*
	 * The search scope must be either LDAP_SCOPE_SUBTREE or
	 * LDAP_SCOPE_ONELEVEL
	 */
	int scope = LDAP_SCOPE_SUBTREE;

	/*
	 * The attribute list to be returned, use {NULL} for getting
	 * all attributes
	 */
	/* char *attrs[] = {"memberOf", NULL}; */

	/*
	 * Specify if only attribute types (1) or both type and value (0)
	 * are returned
	 */
	int attrsonly = 0;

	/* entries_found holds the number of objects found for the LDAP search */
	int entries_found = 0;

	/* dn holds the DN name string of the object(s) returned by the search */
	char *dn = "";

	/* attribute holds the name of the object(s) attributes returned */
	/* char *attribute = ""; */

	/*
	 * values is  array to hold the attribute values of the object(s)
	 * attributes
	 */
	/* struct berval **values; */

	/* int i = 0; */

	log_message(LOG_DEBUG, "plugin invoked");
	/* Read the password */
	if ((pkt_len = vio->read_packet(vio, &password)) < 0)
		return (CR_ERROR);

	myInfo->password_used= PASSWORD_USED_YES;

	/*~ vio->log_message(LOG_INFO, vio, &vio_info); */
	/*~ if (vio_info.protocol != MYSQL_VIO_SOCKET) */
	/*~ return CR_ERROR; */

	LDAP *ld;
	LDAPMessage *answer, *entry;

	log_message(LOG_DEBUG, "connecting to LDAP server %s", CONFIG_LDAP_URI );
	int status = (*ldap_initialize_wrapper)(&ld, CONFIG_LDAP_URI);
	if (status != LDAP_SUCCESS) {
		log_message(LOG_ERR, "connection to server %s failed",
		    CONFIG_LDAP_URI );
		return (CR_ERROR);
	}

	int version = LDAP_VERSION3;

	log_message(LOG_DEBUG, "setting LDAP protocol version to 3");
	status = (*ldap_set_option_wrapper)(ld, LDAP_OPT_PROTOCOL_VERSION,
	    &version);
	if (status != LDAP_OPT_SUCCESS) {
		log_message(LOG_ERR, "cannot set LDAP protocol "
		    "version to 3" );
		(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
		return (CR_ERROR);
	}

	log_message(LOG_DEBUG, "setting LDAP_OPT_X_TLS_CACERTFILE to '%s'", CONFIG_CACERT_FILE);
	status = (*ldap_set_option_wrapper)(ld, LDAP_OPT_X_TLS_CACERTFILE,
	    (void *)CONFIG_CACERT_FILE);
	if (status != LDAP_OPT_SUCCESS) {
		log_message(LOG_ERR, "cannot set LDAP_OPT_X_TLS_CACERTFILE '%s'",
         CONFIG_CACERT_FILE);
		(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
		return (CR_ERROR);
	}

	log_message(LOG_DEBUG, "starting initial bind as '%s'", CONFIG_BIND_DN);
	struct berval* credentials = (*ber_str2bv_wrapper)(
	    (char*)CONFIG_BIND_PW, 0, 0, NULL);
	if (credentials == NULL) {
		log_message(LOG_ERR, "ber_str2bv_wrapper failed");
		(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
		return (CR_ERROR);
	}

	/* Do we need to free the server credentials? */
	/* struct berval* serverCredentials; */

	log_message(LOG_DEBUG, "binding to LDAP server");
	/* status = (*ldap_sasl_bind_s_wrapper)(ld, CONFIG_BIND_DN,
	    LDAP_SASL_SIMPLE, credentials, NULL, NULL, &serverCredentials); */
	status = (*ldap_sasl_bind_s_wrapper)(ld, CONFIG_BIND_DN,
	    LDAP_SASL_SIMPLE, credentials, NULL, NULL, NULL);
	if (status != LDAP_SUCCESS) {
		(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
		log_message(LOG_ERR, "initial bind failed for binddn '%s'", CONFIG_BIND_DN);
		log_message(LOG_DEBUG, "ldap_sasl_bind_s() "
		    "returned: %s", (*ldap_err2string_p)(status));
		return (CR_ERROR);
	} else {
		log_message(LOG_DEBUG, "initial bind succeeded");
		/* Do the LDAP search. */
		status = (*ldap_search_s_wrapper)(ld, CONFIG_DN, scope,
		    CONFIG_SEARCH_FILTER, NULL, attrsonly, &answer);
		    /* CONFIG_SEARCH_FILTER, attrs, attrsonly, &answer); */

		if (status != LDAP_SUCCESS) {
			log_message(LOG_ERR, "LDAP search error: %s",
			    (*ldap_err2string_p)(status));
			(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
			return (CR_ERROR);
		} else
			log_message(LOG_DEBUG, "LDAP search successful");

		char *dn;

		/* uid string, like 'uid=george,' */
		int len = strlen(myInfo->user_name) + 6;
		char *uid_str = (char *)malloc(sizeof(char) * len);
		if (uid_str == NULL) {
			log_message(LOG_ERR, "malloc error creating uid_str");
			(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
			return (CR_ERROR);
		}
		snprintf(uid_str, len, "uid=%s,", myInfo->user_name);
		log_message(LOG_DEBUG, "searching for uid string: %s\n", uid_str);
		/* Cycle through all objects returned with our search */
		for (entry = (*ldap_first_entry_p)(ld, answer);
		    entry != NULL;
		    entry = (*ldap_next_entry_p)(ld, entry)) {

			/* Get DN string of the object */
			dn = (*ldap_get_dn_p)(ld, entry);
			log_message(LOG_DEBUG, "found candidate object: %s", dn);
			/* Search uid from DN */
			if (strstr(dn, uid_str) != NULL) {

				credentials = (*ber_str2bv_wrapper)(
				    (char*)password, 0, 0, NULL);
				if (credentials == NULL) {
					log_message(LOG_ERR, "ber_str2bv_wrapper failed on credentials");
					(*ldap_memfree_p)(dn);
					(*ldap_msgfree_wrapper)(answer);
					(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);
					return (CR_ERROR);
				}
				log_message(LOG_DEBUG, "preparing to bind as "
				    "user dn: '%s'", dn);
				status = (*ldap_sasl_bind_s_wrapper)(ld, dn,
				    LDAP_SASL_SIMPLE, credentials, NULL, NULL,
				    NULL);
				(*ldap_memfree_p)(dn);
				(*ldap_msgfree_wrapper)(answer);
				(*ldap_unbind_ext_wrapper)(ld, NULL, NULL);

				if (status != LDAP_SUCCESS) {
					log_message(LOG_ERR, "authentication failed for user %s (%s): %s",
					    myInfo->user_name, dn,
					    (*ldap_err2string_p)(status) );
					return (CR_ERROR);
				} else {
					log_message(LOG_INFO, "authentication succeeded for user %s",
					    myInfo->user_name);
					return (CR_OK);
				}
			}
			(*ldap_memfree_p)(dn);
		}
		free(uid_str);
		(*ldap_msgfree_wrapper)(answer);
	}
	log_message(LOG_ERR, "authentication failed for user %s: user not found in directory",
	    myInfo->user_name);
	return (CR_ERROR);
}

static struct st_mysql_auth ldap_auth_handler = {
	MYSQL_AUTHENTICATION_INTERFACE_VERSION,
	"mysql_clear_password",		/* required for client-side */
	ldap_auth_server
};

static int
init(void* omited)
{

	log_message(LOG_INFO, "loading module ateam_mysql_ldap_auth (log level %i)", log_level);
	/* config variables */
	const char *_CONFIG_LDAP_URI = NULL;
	const char *_CONFIG_DN = NULL;
	const char *_CONFIG_CACERT_FILE = NULL;
	const char *_CONFIG_BIND_DN = NULL;
	const char *_CONFIG_BIND_PW = NULL;
	const char *_CONFIG_SEARCH_FILTER = NULL;

	cf = &cfg;
	config_init(cf);

	if (!config_read_file(cf, "/usr/local/etc/mysql-auth_ldap.cfg")) {
		log_message(LOG_ERR, "%s:%d - %s",
		    config_error_file(cf),
		    config_error_line(cf),
		    config_error_text(cf));
		config_destroy(cf);
		return (EXIT_FAILURE);
	}
	/* Reading config variables */
	if (config_lookup_string(cf, "ldap.uri", &_CONFIG_LDAP_URI)) {
		CONFIG_LDAP_URI = strdup(_CONFIG_LDAP_URI);
		log_message(LOG_DEBUG, "ldap.uri = %s", CONFIG_LDAP_URI);
	} else {
		log_message(LOG_ERR, "ldap.uri is not defined "
		    "(e.g. ldap:/*localhost:389)");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.cacert_file", &_CONFIG_CACERT_FILE)) {
		CONFIG_CACERT_FILE = strdup(_CONFIG_CACERT_FILE);
		log_message(LOG_DEBUG, "ldap.cacert_file = %s", CONFIG_CACERT_FILE);
	} else {
		log_message(LOG_ERR, "ldap.cacert_file is not defined "
		    "(e.g. /etc/ssl/ldap/ca.crt)");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.bind_dn", &_CONFIG_BIND_DN)) {
		CONFIG_BIND_DN = strdup(_CONFIG_BIND_DN);
		log_message(LOG_DEBUG, "ldap.bind_dn = %s", CONFIG_BIND_DN);
	} else {
		log_message(LOG_ERR, "ldap.bind_dn is not defined "
		    "(e.g. uid=user,ou=People,dc=example,dc=com)");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.bind_pw", &_CONFIG_BIND_PW)) {
		CONFIG_BIND_PW = strdup(_CONFIG_BIND_PW);
		log_message(LOG_DEBUG, "ldap.bind_pw = xxxxxxx");
	} else {
		log_message(LOG_ERR, "ldap.bind_pw is not defined");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.search_filter",
	    &_CONFIG_SEARCH_FILTER)) {
		CONFIG_SEARCH_FILTER = strdup(_CONFIG_SEARCH_FILTER);
		log_message(LOG_DEBUG, "ldap.search_filter = %s",
		    CONFIG_SEARCH_FILTER);
	} else {
		log_message(LOG_ERR, "ldap.search_filter is not defined "
		    "(e.g. (objectClass=inetOrgPerson))");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.dn", &_CONFIG_DN)) {
		CONFIG_DN = strdup(_CONFIG_DN);
		log_message(LOG_DEBUG, "ldap.dn = %s", CONFIG_DN);
	} else {
		log_message(LOG_ERR, "ldap.dn is not defined "
		    "(e.g. ou=People,dc=example,dc=com)");
		return (EXIT_FAILURE);
	}
	if (config_lookup_string(cf, "ldap.libldap", &CONFIG_LIBLDAP))
		log_message(LOG_DEBUG, "ldap.libldap = %s", CONFIG_LIBLDAP);
	else {
		log_message(LOG_ERR, "ldap.libldap is not defined "
		    "(e.g. /usr/lib64/libldap.so)");
		return (EXIT_FAILURE);
	}
	/* End of reading the config file */

	log_message(LOG_DEBUG, "opening OpenLDAP library");
	void *handle = dlopen(CONFIG_LIBLDAP, RTLD_LAZY);
	if (handle == NULL) {
		log_message(LOG_ERR, "cannot open library: %s",
		    CONFIG_LIBLDAP);
		return (EXIT_FAILURE);
	}
	void *initialize = dlsym(handle, "ldap_initialize");
	if (initialize == NULL) {
		log_message(LOG_ERR, "cannot load symbol: "
		    "ldap_initialize");
		return (EXIT_FAILURE);
	}
	void *setOption = dlsym(handle, "ldap_set_option");
	if (setOption == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_set_option");
		return (EXIT_FAILURE);
	}
	void *unbind = dlsym(handle, "ldap_unbind_ext");
	if (unbind == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_unbind_ext");
		return (EXIT_FAILURE);
	}
	void *bind = dlsym(handle, "ldap_sasl_bind_s");
	if (bind == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_sasl_bind_s");
		return (EXIT_FAILURE);
	}
	void *ber = dlsym(handle, "ber_str2bv");
	if (ber == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ber_str2bv");
		return (EXIT_FAILURE);
	}
	void *ber_free = dlsym(handle, "ber_bvfree");
	if (ber_free == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ber_bvfree");
		return (EXIT_FAILURE);
	}
	void *search = dlsym(handle, "ldap_search_s");
	if (search == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_search_s");
		return (EXIT_FAILURE);
	}
	void *first_entry = dlsym(handle, "ldap_first_entry");
	if (first_entry == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_first_entry");
		return (EXIT_FAILURE);
	}
	void *next_entry = dlsym(handle, "ldap_next_entry");
	if (next_entry == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_next_entry");
		return (EXIT_FAILURE);
	}
	void *get_dn = dlsym(handle, "ldap_get_dn");
	if (get_dn == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_get_dn");
		return (EXIT_FAILURE);
	}
	void *msgfree = dlsym(handle, "ldap_msgfree");
	if (msgfree == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_msgfree");
		return (EXIT_FAILURE);
	}
	void *memfree = dlsym(handle, "ldap_memfree");
	if (memfree == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_memfree");
		return (EXIT_FAILURE);
	}
	void *temp = dlsym(handle, "ldap_err2string");
	if (temp == NULL) {
		log_message(LOG_ERR, "cannot load symbol: ldap_err2string");
		return (EXIT_FAILURE);
	}

	ldap_initialize_p = (ldap_initialize_t)initialize;
	ldap_set_option_p = (ldap_set_option_t)setOption;
	ldap_unbind_ext_p = (ldap_unbind_ext_t)unbind;
	ldap_sasl_bind_s_p = (ldap_sasl_bind_s_t)bind;
	ber_str2bv_p = (ber_str2bv_t)ber;
	ldap_search_s_p = (ldap_search_s_t)search;
	ldap_msgfree_p = (ldap_msgfree_t)msgfree;

	ldap_first_entry_p =
	    (LDAPMessage* (*)(LDAP *, LDAPMessage *))first_entry;
	ldap_next_entry_p =
	    (LDAPMessage* (*)(LDAP *, LDAPMessage *))next_entry;
	ldap_get_dn_p = (char* (*)(LDAP *, LDAPMessage *))get_dn;
	ber_bvfree_p = (void (*)(struct berval *))ber_free;
	ldap_memfree_p = (void (*)(void *))memfree;

	ldap_err2string_p = (char* (*)(int))temp;

	libldapHandle = handle;

	return (0);
}

static int
deinit(void* omited)
{

	log_message(LOG_INFO, "unloading module ateam_mysql_ldap_auth");
	/* Close libldap dynamic library */
	if (libldapHandle != NULL) {
		log_message(LOG_DEBUG, "closing OpenLDAP library");
		dlclose(libldapHandle);
	}
	/* Close syslog */
	if (syslog_open) {
		log_message(LOG_DEBUG, "closing syslog, bye!");
		closelog();
	}
	free(CONFIG_SEARCH_FILTER);
	free(CONFIG_BIND_PW);
	free(CONFIG_BIND_DN);
	free(CONFIG_LDAP_URI);
	free(CONFIG_DN);
	config_destroy(cf);

	return (0);
}

mysql_declare_plugin(ldap_auth)
{
	MYSQL_AUTHENTICATION_PLUGIN,		/* Plugin type */
	&ldap_auth_handler,			/* Ptr to plugin descriptor */
	"auth_ldap",				/* Plugin name */
	"A-Team Systems",			/* Author */
	"LDAP authentication server plugin",	/* Description */
	PLUGIN_LICENSE_GPL,			/* License */
	init,					/* On load function */
	deinit,					/* On unload function */
	0x0100,					/* Version */
	NULL,					/* Status vars ?? */
	NULL,					/* System vars ?? */
	NULL,					/* Reserved */
	0,					/* Flags ?? */
} mysql_declare_plugin_end;
