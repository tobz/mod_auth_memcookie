/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_md5.h"
#include "apr_tables.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_base64.h"
#include "memcached.h"

#define ERRTAG "mod_auth_memcookie: "
#define VERSION "1.0.2"

#define unless(c) if(!(c))

/* Declare our Apache module. */
module AP_MODULE_DECLARE_DATA auth_memcookie_module;

/* Holds our configuration data. */
typedef struct {
    char *MemcacheServers;
    apr_time_t MemcacheObjectExpiry;
    int MemcacheObjectExpiryReset;
    int SetSessionHTTPHeader;
    int SetSessionHTTPHeaderEncode;
    int SessionTableSize;
    char *CookieName;
    int GroupAuthoritative;
    int Authoritative;
    int MatchIPMode;
    int SimulateBasicAuth;
} Auth_MemCookie_Config;

static char *Auth_MemCookie_ExtractCookie(request_rec *r, const char *cookieName)
{
    char *cookie = NULL, *rawCookie = NULL, *rawCookieStart = NULL, *rawCookieEnd = NULL;

    /* Make sure we can find a cookie to begin with. */
    rawCookie = (char*)apr_table_get(r->headers_in, "Cookie");
    unless(rawCookie) return 0;

    /* Loop through the Cookie header to try and find our cookie. */
    do {
        /* Try and find the name of our cookie in the header. */
        unless(rawCookie = strstr(rawCookie, cookieName)) return 0;

        /* Set our start point to the beginning of the cookie. */
        rawCookieStart = rawCookie;

        /* Try and find the start of the equals sign for the cookie's key/value pair. */
        unless(rawCookie = strchr(rawCookie, '=')) return 0;
    } while (strncmp(cookieName, rawCookieStart, (rawCookie - rawCookieStart)) != 0);

    /* Skip the equals sign. */
    rawCookie++;

    /* Find the end of the cookie value, be it a separating semicolon or the end of the header itself. */
    unless((rawCookieEnd = strchr(rawCookie, ';')) || (rawCookieEnd = strchr(rawCookie, '\0'))) return 0;

    /* Get our own copy of the cookie's value. */
    unless(cookie = apr_pstrndup(r->pool, rawCookie, (rawCookieEnd - rawCookie))) return 0;

    /* Unescape the value. */
    unless(ap_unescape_url(cookie) == 0) return 0;

    return cookie;
}

static void Auth_MemCookie_AddBasicAuth(request_rec *r, char *password)
{
   char *authHeader = NULL, *encodedAuthHeader = NULL;

   /* See if there's an existing Authorization header. */
   if(apr_table_get(r->headers_in, "Authorization") == NULL)
   {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Adding Authorization header to this request using user '%s'", r->user);

        /* Concatenate username and ':', adding in the password if one was given. */
        if(password != NULL)
        {
            authHeader = (char*)apr_pstrcat(r->pool, r->user, ":", password, NULL);
        }
        else
        {
            authHeader = (char*)apr_pstrcat(r->pool, r->user, ":", NULL);
        }

        /* Allocate enough memory to hold the encoded value. */
        encodedAuthHeader = (char*)apr_palloc(r->pool, apr_base64_encode_len(strlen(authHeader)) + 1);
        unless(encodedAuthHeader)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
            return;
        }

        /* Encode the header value in base64. */
        apr_base64_encode(encodedAuthHeader, authHeader, strlen(authHeader));

        /* Set the Authorization header. */
        apr_table_set(r->headers_in, "Authorization", (char*)apr_pstrcat(r->pool, "Basic ", encodedAuthHeader, NULL));

        /* Force the authentication type to basic. */
        r->ap_auth_type = apr_pstrdup(r->pool, "Basic");
   }
}

static apr_table_t *Auth_MemCookie_GetSession(request_rec *r, char *cookieValue)
{
    memcached_st *mc_session = NULL;
    memcached_server_st *mc_servers = NULL;
    memcached_return_t mc_ret;
    memcached_return_t mc_err;

    Auth_MemCookie_Config *conf = NULL;
    apr_table_t *session = NULL;
    size_t valueLen = 0;
    uint32_t flags = 0;
    char *tokenPos;
    char *fieldTokenPos;
    char *field;
    char *value;
    char *fieldName;
    char *fieldValue;
    char *dupValue;
    int entryCount = 0;

     /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &auth_memcookie_module);

    /* Initialize our memcache object. */
    mc_session = memcached_create(NULL);
    unless(mc_session)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Failed to initialize memcache.");
        return NULL;
    }

    unless(session = apr_table_make(r->pool, conf->SessionTableSize))
    {
       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_table_make failed");
       return NULL;
    }

    /* Parse the list of memcached servers from the configuration. */
    unless(mc_servers = memcached_servers_parse(conf->MemcacheServers))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Failed to parse memcache endpoints!");
        return NULL;
    }

    /* Feed to servers to our memcache object. */
    mc_ret = memcached_server_push(mc_session, mc_servers);
    if(mc_ret != MEMCACHED_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Failed to add endpoints to memcache object, return code: %d", mc_ret);
        return NULL;
    }

    /* Find our session information in memcache based on our cookie value. */
    value = memcached_get(mc_session, cookieValue, strlen(cookieValue), &valueLen, &flags, &mc_err);
    if(mc_err != MEMCACHED_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "Failed to find session in memcache with key '%s'", cookieValue);
        return NULL;
    }

    /* Make sure we actually got something back. */
    if(value == NULL)
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Got no data from memcache for key '%s'", cookieValue);
        return NULL;
    }

    /* Duplicate the value we got back so we have our own copy. */
    dupValue = apr_pstrdup(r->pool, value);

    /* Read in the session information.  Should be a multi-line blob with key/value pairs written as key=value. */
    tokenPos = NULL;
    for(field = strtok_r(dupValue, "\r\n", &tokenPos); field; field = strtok_r(NULL, "\r\n", &tokenPos))
    {
        fieldTokenPos = NULL;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Read session field: %s", field);

        fieldName = strtok_r(field, "=", &fieldTokenPos);
        fieldValue = strtok_r(NULL, "=", &fieldTokenPos);
        if (fieldName != NULL && fieldValue != NULL)
        {
            /* Add the key/value pair to the session table object. */
            apr_table_set(session, fieldName, fieldValue);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Read session key/value pair: '%s' -> '%s'", fieldName, fieldValue);

            /* Make sure we haven't gone over the size of our session object. */
            entryCount++;
            if (entryCount > conf->SessionTableSize)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Exceeded size of session table object! Table size: %d", conf->SessionTableSize);
                return NULL;
            }
        }
    }

    /* Make sure that username was included in the session information. */
    unless(apr_table_get(session, "Username"))
    {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Username not present in session data! Cookie value: %s Session data: %s", cookieValue, value);
       session = NULL;
    }

    /* See if we have IP matching enabled and, if so, make sure we have the remote IP for the user in their session information. */
    if(conf->MatchIPMode != 0 && !apr_table_get(session, "RemoteIP"))
    {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "IP matching enabled and RemoteIP not present in session data! Cookie value: %s Session data: %s", cookieValue, value);
       session = NULL;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Found session data for key '%s'. Username: %s Groups: %s Remote IP: %s", cookieValue, apr_table_get(session, "Username"), apr_table_get(session, "Groups"), apr_table_get(session, "RemoteIP"));

    /* Reset the session in memcache to reset the expiration, if enabled. */
    if(conf->MemcacheObjectExpiryReset && session)
    {
        mc_ret = memcached_set(mc_session, (const char *)cookieValue, strlen(cookieValue), (const char *)value, valueLen, conf->MemcacheObjectExpiry, 0);
        if(mc_ret != MEMCACHED_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG  "Failed to update session data with new expiration time.  Cookie value: %s Error code: %d", cookieValue, mc_ret);
            session = NULL;
        }
    }

    /* Free the data we got back from memcached. */
    if(!value)
    {
        free(value);
    }

    /* Clean up our memcache object. */
    memcached_free(mc_session);

    /* Set the username for this request from our authentication data. */
    if(session != NULL && apr_table_get(session, "Username") != NULL)
    {
        r->user = (char*)apr_table_get(session, "Username");
    }

    return session;
}

static int Auth_MemCookie_CheckGroups(request_rec *r, char *group, char *groups)
{
    char *groupEnd = NULL, *groupPos = NULL, *dupGroups = NULL;

    /* Make a copy of the groups. */
    dupGroups = apr_pstrdup(r->pool, groups);

    /* See if the specified group is within the groups overall. */
    unless(groupPos = strstr(dupGroups, group)) return DECLINED;

    /* If there is a colon after our match, turn it into a null-terminating byte. */
    if((groupEnd = strchr(groupPos, ':')))
    {
        groupEnd[0] = '\0';
    }

    /* Now make sure our match was exact and not just a partial. */
    if(strcmp(group, groupPos)) return DECLINED;

    return OK;
}


/* user apr_table_do to set session information in child environment variable */
static int Auth_MemCookie_DoSetEnv(void *rec, const char *key, const char *value)
{
    request_rec *r = (request_rec*)rec;
    char *envName = apr_pstrcat(r->pool, "MAMC_", key, NULL);

    /* Set the environment variable. */
    apr_table_setn(r->subprocess_env, envName, value);

    return 1;
}

/* user apr_table_do to set session information in header http */
static int Auth_MemCookie_DoSetHeader(void *rec, const char *key, const char *value)
{
    Auth_MemCookie_Config *conf = NULL;
    request_rec *r = (request_rec*)rec;
    char *encodedHeader = NULL;
    char *headerName = apr_pstrcat(r->pool, "X-MAMC_", key, NULL);

    /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &auth_memcookie_module);

    if(conf->SetSessionHTTPHeaderEncode)
    {
        /* Allocate memory for the estimated size of the encoded header. */
        encodedHeader = (char*)apr_palloc(r->pool, (apr_base64_encode_len(strlen(value)) + 1));
        unless(encodedHeader)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Failed to allocate memory for encoding HTTP header '%s'!", headerName);
            return 0;
        }

        /* Encode string in base64 format. */
        apr_base64_encode(encodedHeader, value, strlen(value));

        /* Set the header. */
        apr_table_set(r->headers_in, headerName, encodedHeader);
    }
    else
    {
        /* Set the header. */
        apr_table_set(r->headers_in, headerName, (char*)value);
    }

    return 1;
}

static int Auth_MemCookie_CheckCookie(request_rec *r)
{
    Auth_MemCookie_Config *conf = NULL;
    char *cookieValue = NULL, remoteIP = NULL;
    apr_table_t *authSession = NULL;
    apr_status_t retStatus;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Entering Auth_MemCookie_CheckCookie");

    /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &auth_memcookie_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "IP matching mode: %d", conf->MatchIPMode);

    /* Grab the remote IP of the user if we're doing IP matching. */
    if(conf->MatchIPMode == 2 && apr_table_get(r->headers_in, "Via") != NULL)
    {
        remoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "Via"));
    }
    else if(conf->MatchIPMode == 1 && apr_table_get(r->headers_in, "X-Forwarded-For") != NULL)
    {
        remoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "X-Forwarded-For"));
    }
    else if(conf->MatchIPMode == 3)
    {
        remoteIP = apr_pstrdup(r->pool, r->connection->remote_ip);
    }

    /* Check if we're authoritative. */
    unless(conf->Authoritative) return DECLINED;

    /* Make sure the authorization type is 'Cookie'. */
    unless(strncmp("Cookie", ap_auth_type(r), 6) == 0)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication type must be set to Cookie e.g. AuthType Cookie - forbidden");
        return HTTP_UNAUTHORIZED;
    }

    /* Make sure there's a cookie name specified. */
    unless(conf->CookieName)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication cookie name must be specified - forbidden");
        return HTTP_UNAUTHORIZED;
    }

    /* Make sure we have Memcache servers defined. */
    unless(conf->MemcacheServers)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication requires Memcache; servers must be specified - forbidden");
        return HTTP_UNAUTHORIZED;
    }

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Memcache servers: %s", conf->MemcacheServers);

    /* Make sure the request has the cookie we're looking for. */
    unless(cookieValue = Auth_MemCookie_ExtractCookie(r, conf->CookieName))
    {
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Authentication cookie not found - forbidden");
        return HTTP_UNAUTHORIZED;
    }

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Found authentication cookie '%s': %s", conf->CookieName, cookieValue);

    /* Pull the user's session out of Memcache. */
    unless(authSession = Auth_MemCookie_GetSession(r, cookieValue))
    {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "No session found for key '%s' - forbidden", cookieValue);
        return HTTP_UNAUTHORIZED;
    }

    /* Store the user's session information in this request so we can authorize the request after authentication. */
    if((retStatus = apr_pool_userdata_setn(authSession, "SESSION", NULL, r->pool)))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Failed to store the session data in the request - forbidden", retStatus);
        return HTTP_UNAUTHORIZED;
    }

    /* If IP matching is enabled, check it now. */
    if(conf->MatchIPMode != 0)
    {
        if(strcmp(remoteIP, (char*)apr_table_get(authSession, "RemoteIP")))
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "IP matching enabled. User's IP does not match session data.  User: %s Remote IP: %s Session IP: %s - forbidden", (char*)apr_table_get(authSession, "Username"), remoteIP, (char*)apr_table_get(authSession, "RemoteIP"));
            return HTTP_UNAUTHORIZED;
        }
    }

    /* Set our session data as environmental variables - all variables prefixed with 'MCAC' e.g. MCAC_Username */
    apr_table_do(Auth_MemCookie_DoSetEnv, r, authSession, NULL);

    /* Set REMOTE_USER as an environmental variable so scripts can easily find it. */
    apr_table_setn(r->subprocess_env, "REMOTE_USER", apr_table_get(authSession, "Username"));

    /* Set our session data as HTTP headers, if enabled. */
    if(conf->SetSessionHTTPHeader)
    {
        apr_table_do(Auth_MemCookie_DoSetHeader, r, authSession, NULL);
    }

    /* If basic authentication compatability mode is enabled, "switch" this request to it and
     * populate the Authorization header accordingly. */
    if(conf->SimulateBasicAuth)
    {
        Auth_MemCookie_AddBasicAuth(r, (char*)apr_table_get(authSession, "Password"));
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Authentication successful for current user '%s'", apr_table_get(authSession, "Username"));

    return OK;
}

static int Auth_MemCookie_CheckAuth(request_rec *r)
{
    Auth_MemCookie_Config *conf = NULL;
    char *currentUser = r->user;
    int m = r->method_number;
    const apr_array_header_t *reqs_arr = NULL;
    require_line *reqs = NULL;
    int x = 0;
    const char *requireLine;
    char *requiredUser = NULL, *requireValue = NULL, *group = NULL, *groups = NULL;
    apr_table_t *authSession = NULL;
    apr_status_t tRetStatus;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Entering Auth_MemCookie_CheckAuth");

    /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &auth_memcookie_module);

    /* Check if we're authoritative. */
    unless(conf->Authoritative) return DECLINED;

    /* Check if we're group authoritative. */
    unless(conf->GroupAuthoritative) return DECLINED;

    if((tRetStatus = apr_pool_userdata_get((void**)&authSession, "SESSION", r->pool)))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Caught an error while calling apr_pool_userdata_get, error code: %d", tRetStatus);
        return HTTP_FORBIDDEN;
    }

    /* Get all the Require directives pertinent to this request. */
    reqs_arr = ap_requires(r);
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* Decline if there's no requires. */
    unless(reqs_arr) return DECLINED;

    /* Walk through each Requires directive, seeing if any of them match. */
    for (x = 0; x < reqs_arr->nelts; x++)
    {
        unless((reqs[x].method_mask & (AP_METHOD_BIT << m))) continue;

        requireLine = reqs[x].requirement;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Current require line: '%s'", requireLine);

        /* Get the first word in directive i.e. Require valid-user -> 'valid-user' */
        requireValue = ap_getword_white(r->pool, &requireLine);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Current require line value: '%s'", requireValue);

        /* If the requirement is just having a valid user, then we're good here implicitly. */
        if(!strcmp("valid-user", requireValue))
        {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Requirement is 'valid-user'; implicitly satisfied - authorized");
            return OK;
        }
        else if(!strcmp("user", requireValue))
        {
            /* If this is a specific user to validate as, see if we match. */
            requiredUser = ap_getword_conf(r->pool, &requireLine);
            if(strcmp(currentUser, requiredUser))
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG  "Current user '%s' doesn't match required user '%s' - forbidden", currentUser, requiredUser);
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Current user '%s' matches required user '%s' - authorized", currentUser, requiredUser);
            return OK;
        }
        else if(!strcmp("group", requireValue))
        {
            groups = (char*)apr_table_get(authSession, "Groups");
            group = ap_getword_white(r->pool, &requireLine);

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Checking group '%s' in '%s'", group, groups);

            /* See if the user is even in any groups.  If not, then they can't possibly be authorized. */
            if(groups == NULL)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "Current user '%s' not in group '%s' - forbidden", currentUser, group);
                return HTTP_FORBIDDEN;
            }

            /* See if the group required is a group the user is in. */
            if(Auth_MemCookie_CheckGroups(r, group, groups) != OK)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG  "Current user '%s' not in groups - forbidden", currentUser);
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Current user '%s' is member of group '%s' - authorized", currentUser, group);
            return OK;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG  "Unable to authorize current user '%s' - forbidden", currentUser);

    /* Forbidden by default. */
    return HTTP_FORBIDDEN;
}

static void Auth_MemCookie_RegisterHooks(apr_pool_t *p)
{
    ap_hook_check_user_id(Auth_MemCookie_CheckCookie, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_auth_checker(Auth_MemCookie_CheckAuth, NULL, NULL, APR_HOOK_FIRST);
}

static void *Auth_MemCookie_CreateDefaultConfig(apr_pool_t *p, char *d)
{
    Auth_MemCookie_Config *conf = apr_palloc(p, sizeof(*conf));

    conf->CookieName = apr_pstrdup(p, "AuthMemCookie");
    conf->MemcacheServers = apr_pstrdup(p, "127.0.0.1:11211");
    conf->MemcacheObjectExpiry = 3600;
    conf->MemcacheObjectExpiryReset = 1;
    conf->MatchIPMode = 0;
    conf->GroupAuthoritative = 1;
    conf->Authoritative = 0;
    conf->SimulateBasicAuth = 1;
    conf->SetSessionHTTPHeader = 0;
    conf->SetSessionHTTPHeaderEncode = 1;
    conf->SessionTableSize = 10;

    return conf;
}

static const char *Auth_MemCookie_MatchIPMode(cmd_parms *cmd, void *InDirConf, const char *p1)
{
    Auth_MemCookie_Config *conf = (Auth_MemCookie_Config*)InDirConf;

    if (strcasecmp("1", p1) == 0)
    {
        /* Use the X-Forwarded-For HTTP header. */
        conf->MatchIPMode = 1;
    }
    else if (strcasecmp("2", p1) == 0)
    {
        /* Use the Via HTTP Header. */
        conf->MatchIPMode = 2;
    }
    else if (strcasecmp("3", p1) == 0)
    {
        /* Use Apache's internal remote IP value. */
        conf->MatchIPMode = 3;
    }
    else
    {
        /* No IP matching. */
        conf->MatchIPMode = 0;
    }

    return NULL;
}

/* Configuration entries for this module. */
static const command_rec Auth_MemCookie_commandTable[] =
{
    AP_INIT_TAKE1("Auth_MemCookie_MemcacheServers", ap_set_string_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, MemcacheServers), OR_AUTHCFG, "Comma-separated list of memcached servers - defaults to '127.0.0.1:11211'."),
    AP_INIT_TAKE1("Auth_MemCookie_Memcache_Expiration", ap_set_int_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, MemcacheObjectExpiry), OR_AUTHCFG, "Expiration time for sessions, in seconds.  Defaults to one hour."),
    AP_INIT_FLAG("Auth_MemCookie_Memcache_ExpirationReset", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, MemcacheObjectExpiryReset), OR_AUTHCFG, "Reset expiration time of session on each request.  Defaults to 'yes'."),
    AP_INIT_TAKE1("Auth_MemCookie_SessionTableSize", ap_set_int_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, SessionTableSize), OR_AUTHCFG, "Maximum number of concurrent sessions.  Defaults to 10."),
    AP_INIT_FLAG("Auth_MemCookie_SetSessionHTTPHeader", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, SetSessionHTTPHeader), OR_AUTHCFG, "Whether or not to add the session data as HTTP headers.  Defaults to 'no'."),
    AP_INIT_FLAG("Auth_MemCookie_SetSessionHTTPHeaderEncode", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, SetSessionHTTPHeaderEncode), OR_AUTHCFG, "Whether or not to base64 encode session data HTTP headers.  Defaults to 'no'."),
    AP_INIT_TAKE1("Auth_MemCookie_CookieName", ap_set_string_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, CookieName), OR_AUTHCFG, "The name of the cookie used for holding session information.  Defaults to 'AuthMemCookie'."),
    AP_INIT_TAKE1("Auth_MemCookie_MatchIPMode", Auth_MemCookie_MatchIPMode, NULL, OR_AUTHCFG, "Matches IP recorded in session to current IP. Possible values: disabled (0), X-Forwarded-For (1), Via (2), or Apache 'REMOTE_IP' (3).  Defaults to 0."),
    AP_INIT_FLAG("Auth_MemCookie_GroupAuthoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, GroupAuthoritative), OR_AUTHCFG, "Allow group access control to be passed along to lower modules.  Defaults to 'yes'."),
    AP_INIT_FLAG("Auth_MemCookie_Authoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, Authoritative), OR_AUTHCFG, "Allow access control to be passed along to lower modules.  Defaults to 'no'."),
    AP_INIT_FLAG("Auth_MemCookie_SimulateBasicAuth", ap_set_flag_slot, (void *)APR_OFFSETOF(Auth_MemCookie_Config, SimulateBasicAuth), OR_AUTHCFG, "Whether or not to emulate the Authorization header with session data. Defaults to 'yes'."),
    {NULL}
};

/* Define the structure of the module. */
module AP_MODULE_DECLARE_DATA auth_memcookie_module =
{
    STANDARD20_MODULE_STUFF,
    Auth_MemCookie_CreateDefaultConfig, /* Creates a default config for the module. */
    NULL,                               /* Directory merger; default is override. */
    NULL,                               /* Server config. */
    NULL,                               /* Merge server config. */
    Auth_MemCookie_commandTable,        /* Our command (how to parse config values) table. */
    Auth_MemCookie_RegisterHooks        /* Register hooks. */
};
