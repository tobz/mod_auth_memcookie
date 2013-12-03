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

#define ERRTAG "Auth_MemCookie: "
#define VERSION "1.0.2"

#define unless(c) if(!(c))

/* Declare our Apache module. */
module AP_MODULE_DECLARE_DATA mod_auth_memcookie_module;

/* Holds our configuration data. */
typedef struct {
    char *Memcache_Servers;
    apr_time_t MemcacheObjectExpiry;
    int MemcacheObjectExpiryReset;

    int SetSessionHTTPHeader;
    int SetSessionHTTPHeaderEncode;
    int SessionTableSize;

    char *CookieName;

    int GroupAuthoritative;
    int Authoritative;
    int MatchIPMode;

    int BasicAuthCompatability;
} Auth_MemCookie_Config;

/* Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
static char *extract_cookie(request_rec *r, const char *szCookie_name) 
{
  char *szRaw_cookie_start=NULL, *szRaw_cookie_end;
  char *szCookie;
  /* get cookie string */
  char*szRaw_cookie = (char*)apr_table_get( r->headers_in, "Cookie");
  unless(szRaw_cookie) return 0;

  /* loop to search cookie name in cookie header */
  do {
    /* search cookie name in cookie string */
    unless (szRaw_cookie =strstr(szRaw_cookie, szCookie_name)) return 0;
    szRaw_cookie_start=szRaw_cookie;
    /* search '=' */
    unless (szRaw_cookie = strchr(szRaw_cookie, '=')) return 0;
  } while (strncmp(szCookie_name,szRaw_cookie_start,szRaw_cookie-szRaw_cookie_start)!=0);

  /* skip '=' */
  szRaw_cookie++;

  /* search end of cookie name value: ';' or end of cookie strings */
  unless ((szRaw_cookie_end = strchr(szRaw_cookie, ';')) || (szRaw_cookie_end = strchr(szRaw_cookie, '\0'))) return 0;

  /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
  unless (szCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie)) return 0;
  /* unescape the value string */ 
  unless (ap_unescape_url(szCookie) == 0) return 0;

  return szCookie;
}

/* function to fix any headers in the input request that may be relied on by an
   application. e.g. php uses the Authorization header when logging the request
   in apache and not r->user (like it ought to). It is applied after the request
   has been authenticated. */
static void fix_headers_in(request_rec *r,char*szPassword)
{

   char *szUser=NULL;

   /* Set an Authorization header in the input request table for php and
      other applications that use it to obtain the username (mainly to fix
      apache logging of php scripts). We only set this if there is no header
      already present. */

   if (apr_table_get(r->headers_in,"Authorization")==NULL) 
   {

     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "fixing apache Authorization header for this request using user:%s",r->user);

     /* concat username and ':' */
     if (szPassword!=NULL) szUser=(char*)apr_pstrcat(r->pool,r->user,":",szPassword,NULL);
     else szUser=(char*)apr_pstrcat(r->pool,r->user,":",NULL);

     /* alloc memory for the estimated encode size of the username */
     char *szB64_enc_user=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szUser))+1);
     unless (szB64_enc_user) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
       return;
     }

     /* encode username in base64 format */
     apr_base64_encode(szB64_enc_user,szUser,strlen(szUser));


     /* set authorization header */
     apr_table_set(r->headers_in,"Authorization", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));

     /* force auth type to basic */
     r->ap_auth_type=apr_pstrdup(r->pool,"Basic");
   }
 
   return;
} 

static apr_table_t *Auth_MemCookie_GetSession(request_rec *r, Auth_MemCookie_Config *conf, char *cookieValue)
{
    apr_time_t tExpireTime = conf->MemcacheObjectExpiry;
    memcached_st *mc_session = NULL;
    memcached_server_st *mc_servers = NULL;
    memcached_return_t mc_ret;
    memcached_return_t mc_err;

    apr_table_t *pMySession = NULL;
    size_t nGetLen=0;
    uint32_t flags = 0;
    char *szTokenPos;
    char *szFieldTokenPos;
    char *szField;
    char *szValue;
    char *szFieldName;
    char *szFieldValue;
    char *szMyValue;
    int nbInfo=0;

    /* Initialize our memcache object. */
    mc_session = memcached_create(NULL);
    unless(mc_session)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Failed to initialize memcache.");
        return NULL;
    }

    unless(pMySession = apr_table_make(r->pool, conf->SessionTableSize))
    {
       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_table_make failed");
       return NULL;
    }

    /* Parse the list of memcached servers from the configuration. */
    mc_servers = memcached_servers_parse(conf->Memcache_Servers);
    if(mc_servers == NULL)
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
    szValue = memcached_get(mc_session, cookieValue, strlen(cookieValue), &nGetLen, &flags, &mc_err);
    if(mc_err != MEMCACHED_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "Failed to find session in memcache with key '%s': %s", cookieValue, memcached_last_error_message(mc_session));
        return NULL;
    }

    /* Make sure we actually got something back. */
    if(szValue == NULL)
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "memcached_get returned no data for key '%s'", cookieValue);
        return NULL;
    }

    /* dup szValue in pool */
    szMyValue = apr_pstrdup(r->pool,szValue);

    /* split szValue into struct strAuthSession */
    /* szValue is formated multi line (\r\n) with name=value on each line */
    /* must containe UserName,Groups,RemoteIP fieldname */
    szTokenPos=NULL;
    for(szField=strtok_r(szMyValue,"\r\n",&szTokenPos);szField;szField=strtok_r(NULL,"\r\n",&szTokenPos)) {
        szFieldTokenPos=NULL;
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session field:%s",szField);
        szFieldName=strtok_r(szField,"=",&szFieldTokenPos);
        szFieldValue=strtok_r(NULL,"=",&szFieldTokenPos);
        if (szFieldName!=NULL&&szFieldValue!=NULL) {
            /* add key and value in pMySession table */
            apr_table_set(pMySession,szFieldName,szFieldValue);
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session information %s=%s",szFieldName,szFieldValue);

            /* count the number of element added to table to check table size not reached */
            nbInfo++;
            if (nbInfo>conf->nAuth_MemCookie_SessionTableSize) {
                ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "maximum session information reached!");
                return NULL;
            }
        }
    }

    if (!apr_table_get(pMySession,"UserName"))
    {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Username not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else if (conf->nAuth_MemCookie_MatchIP_Mode!=0&&!apr_table_get(pMySession,"RemoteIP")) {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "MatchIP_Mode activated and RemoteIP not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else {
       ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Value for Session (key:%s) found => Username=%s Groups=%s RemoteIp=%s",
				 szCookieValue,
				 apr_table_get(pMySession,"UserName"),
				 apr_table_get(pMySession,"Groups"),
				 apr_table_get(pMySession,"RemoteIP"));
			      }

    /* Reset the session in memcache to reset the expiration, if enabled. */
    if(conf->MemcacheObjectExpiryReset && pMySession)
    {
        mc_ret = memcached_set(mc_session, (const char *)cookieValue, strlen(cookieValue), (const char *)szValue, nGetLen, tExpireTime, 0);
        if(mc_ret != MEMCACHED_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG  "Expire time with memcached_set (key:%s) failed with errcode=%d",szCookieValue,mc_ret);
            pMySession = NULL;
        }
    }

    /* free aget2 retruned valued */
    if (!szValue) free(szValue);

    /* Clean up our memcache object. */
    memcached_free(mc_session);

    /* set the good username found in request structure */
    if(pMySession != NULL && apr_table_get(pMySession, "UserName") != NULL)
    {
        r->user = (char*)apr_table_get(pMySession, "UserName");
    }

    return pMySession;
}

/* check if szGroup are in szGroups. */
static int get_Auth_MemCookie_grp(request_rec *r, char *szGroup, char *szGroups)
{
    char *szGrp_End;
    char *szGrp_Pos;
    char *szMyGroups;

    /* make a copy */
    szMyGroups=apr_pstrdup(r->pool,szGroups);
    /* search group in groups */
    unless(szGrp_Pos=strstr(szMyGroups,szGroup)) {
      return DECLINED;
    }
    /* search the next ':' and set '\0' in place of ':' */
    if ((szGrp_End=strchr(szGrp_Pos,':'))) szGrp_End[0]='\0';

    /* compar szGroup with szGrp_Pos if ok return ok */
    if(strcmp(szGroup,szGrp_Pos))
       return DECLINED;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "group found=%s",szGrp_Pos);
    return OK;
}


/* user apr_table_do to set session information in child environment variable */
static int Auth_MemCookie_DoSetEnv(void*rec,const char *szKey, const char *szValue)
{
    request_rec *r=(request_rec*)rec;
    char*szEnvName=apr_pstrcat(r->pool,"MCAC_",szKey,NULL);
    /* set env var MCAC_USER to the user session value */
    apr_table_setn(r->subprocess_env,szEnvName,szValue);
    return 1;
}

/* user apr_table_do to set session information in header http */
static int Auth_MemCookie_DoSetHeader(void*rec,const char *szKey, const char *szValue)
{
    strAuth_MemCookie_config_rec *conf=NULL;
    request_rec *r=(request_rec*)rec;
    char *szHeaderName=apr_pstrcat(r->pool,"X-MCAC_",szKey,NULL);

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    if (conf->nAuth_MemCookie_SetSessionHTTPHeaderEncode) {
      /* alloc memory for the estimated encode size of the string */
      char *szB64_enc_string=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szValue))+1);
      unless (szB64_enc_string) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc for encoding http header failed!");
	return 0;
      }

      /* encode string in base64 format */
      apr_base64_encode(szB64_enc_string,szValue,strlen(szValue));

      /* set string header */
      apr_table_set(r->headers_in,szHeaderName, (char*)szB64_enc_string);
    }
    else
    {
      /* set string header */
      apr_table_set(r->headers_in,szHeaderName, (char*)szValue);
    }
    return 1;
}

static int Auth_MemCookie_CheckCookie(request_rec *r)
{
    Auth_MemCookie_Config *conf = NULL;
    char *cookieValue = NULL;
    apr_table_t *authSession = NULL;
    apr_status_t retStatus;
    char *remoteIP = NULL;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "Entering Auth_MemCookie_CheckCookie");

    /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "IP matching mode: %d", conf->MatchIPMode);

    /* Grab the remote IP of the user if we're doing IP matching. */
    if(conf->MatchIPMode == 2 && apr_table_get(r->headers_in, "Via") != NULL)
    {
        remoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "Via"));
    }
    else if(conf->MatchIP_Mode == 1 && apr_table_get(r->headers_in, "X-Forwarded-For") != NULL)
    {
        remoteIP = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "X-Forwarded-For"));
    }
    else if(conf->MatchIPMode == 3)
    {
        remoteIP = apr_pstrdup(r->pool, r->connection->remote_ip);
    }

    /* Check if we're authoritative. */
    unless(conf->Authoritative)
    {
        return DECLINED;
    }

    /* Make sure the authorization type is 'Cookie'. */
    unless(strncmp("Cookie", ap_auth_type(r), 6) == 0)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication type must be set to Cookie e.g. AuthType Cookie");
        return HTTP_UNAUTHORIZED;
    }

    /* Make sure there's a cookie name specified. */
    unless(conf->CookieName)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication cookie name must be specified!");
        return HTTP_UNAUTHORIZED;
    }

    /* Make sure we have MEmcache servers defined. */
    unless(conf->Memcache_Servers)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Authentication requires Memcache - servers must be specified!");
        return HTTP_UNAUTHORIZED;
    }

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG  "Memcache servers: %s", conf->Memcache_Servers);

    /* Make sure the request has the cookie we're looking for. */
    unless(cookieValue = extract_cookie(r, conf->CookieName))
    {
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Authentication cookie not found!");
        return HTTP_UNAUTHORIZED;
    }

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Found authentication cookie '%s': %s", conf->CookieName, cookieValue);

    /* Pull the user's session out of Memcache. */
    if((authSession = Auth_MemCookie_get_session(r, conf, cookieValue)) == NULL)
    {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "AuthSession %s not found: %s", cookieValue, r->filename);
        return HTTP_UNAUTHORIZED;
    }

    /* Store the user's session information in this request so we can authorize the request after authentication. */
    if((retStatus = apr_pool_userdata_setn(authSession, "SESSION", NULL, r->pool)))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "apr_pool_userdata_setn Apr Error: %d", tRetStatus);
        return HTTP_UNAUTHORIZED;
    }

    /* check remote ip if option is enabled */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "check ip: remote_ip=%s cookie_ip=%s", remoteIP, apr_table_get(authSession, "RemoteIP"));
    if(conf->nAuth_MemCookie_MatchIP_Mode != 0)
    {
        if(strcmp(remoteIP, apr_table_get(authSession, "RemoteIP")))
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unauthorized, by ip. user:%s remote_ip:%s != cookie_ip:%s", apr_table_get(authSession, "UserName"), remoteIP, apr_table_get(authSession, "RemoteIP"));
            return HTTP_UNAUTHORIZED;
        }
    }

    /* set env var MCAC_ to the information session value */
    apr_table_do(Auth_MemCookie_DoSetEnv, r, authSession, NULL);

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env, "REMOTE_USER", apr_table_get(authSession, "UserName"));

    /* set MCAC-SESSIONKEY var for scripts language */
    apr_table_setn(r->subprocess_env, "MCAC_SESSIONKEY", cookieValue);

    /* set in http header the session value */
    if(conf->nAuth_MemCookie_SetSessionHTTPHeader)
    {
        apr_table_do(Auth_MemCookie_DoSetHeader, r, authSession, NULL);
    }

    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "authentication ok");

    /* fix http header for php */
    if(conf->nAuth_MemCookie_BasicAuthCompatability)
    {
        fix_headers_in(r, (char*)apr_table_get(authSession, "Password"));
    }

    /* if all is ok return auth ok */
    return OK;
}

static int Auth_MemCookie_CheckAuth(request_rec *r)
{
    Auth_MemCookie_Config *conf = NULL;
    char *szCurrentUser = r->user;
    int m = r->method_number;
    const apr_array_header_t *reqs_arr = NULL;
    require_line *reqs = NULL;
    int x;
    const char *szRequireLine;
    char *szRequiredUser, *szRequireValue, *szGroup, *szGroups;
    apr_table_t *pAuthSession = NULL;
    apr_status_t tRetStatus;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Entering Auth_MemCookie_CheckAuth");

    /* Get our configuration. */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    /* Check if we're authoritative. */
    unless(conf->Authoritative)
        return DECLINED;

    /* Check if we're group authoritative. */
    unless(conf->GroupAuthoritative)
        return DECLINED;

    if(tRetStatus = apr_pool_userdata_get((void**)&pAuthSession, "SESSION", r->pool))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Caught an error while calling apr_pool_userdata_get, error code: %d", tRetStatus);
        return HTTP_FORBIDDEN;
    }

    /* Get all the Require directives pertinent to this request. */
    reqs_arr = ap_requires(r);
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* Decline if there's no requires. */
    if (!reqs_arr)
        return DECLINED;

    /* Walk through each Requires directive, seeing if any of them match. */
    for (x = 0; x < reqs_arr->nelts; x++)
    {
        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
            continue;

        szRequireLine = reqs[x].requirement;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Current require line: '%s'", szRequireLine);

        /* Get the first word in directive i.e. Require valid-user -> 'valid-user' */
        szRequireValue = ap_getword_white(r->pool, &szRequireLine);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Current require line value: '%s'", szRequireValue);

        /* If the requirement is just having a valid user, then we're good here implicitly. */
        if (!strcmp("valid-user", szRequireValue))
        {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Requirement is 'valid-user'; implicitly satisfied - authorized");
            return OK;
        }
        else if (!strcmp("user", szRequireValue))
        {
            /* If this is a specific user to validate as, see if we match. */
            szRequiredUser = ap_getword_conf(r->pool, &szRequireLine);
            if(strcmp(szCurrentUser, szRequiredUser))
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG  "Current user '%s' doesn't match user required '%s' - forbidden", szCurrentUser, szRequiredUser);
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Current user '%s' matches required user '%s' - authorized", szCurrentUser, szRequiredUser);
            return OK;
        }
        else if (!strcmp("group", szRequireValue))
        {
            szGroups = (char*)apr_table_get(pAuthSession, "Groups");
            szGroup = ap_getword_white(r->pool, &szRequireLine);

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Checking group '%s' in '%s'", szGroup, szGroups);

            if(szGroups == NULL)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "Current user '%s' not in group '%s' - forbidden", szCurrentUser, szGroup);
                return HTTP_FORBIDDEN;
            }

            if (get_Auth_MemCookie_grp(r, szGroup, szGroups) != OK)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG  "Current user '%s' not in groups - forbidden", szCurrentUser);
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG  "Current user '%s' is member of group '%s' - accepted", szCurrentUser, szGroup);
            return OK;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG  "Unable to authorizer current user '%s' - forbidden", szCurrentUser);

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
    conf->BasicAuthCompatability = 1;
    conf->SetSessionHTTPHeader = 0;
    conf->SetSessionHTTPHeaderEncode = 1;
    conf->SessionTableSize = 10;

    return conf;
}

static const char *cmd_MatchIP_Mode(cmd_parms *cmd, void *InDirConf, const char *p1)
{
    Auth_MemCookie_Config *conf = (Auth_MemCookie_Config*)InDirConf;

    if (strcasecmp("1", p1) == 0)
    {
       conf->MatchIPMode = 1;
    }
    else if (strcasecmp("2", p1) == 0)
    {
       conf->MatchIPMode = 2;
    }
    else if (strcasecmp("3", p1) == 0)
    {
       conf->MatchIPMode = 3;
    }
    else
    {
       conf->MatchIPMode=0;
    }

    return NULL;
}

/* Configuration entries for this module. */
static const command_rec Auth_MemCookie_commandTable[] =
{
    AP_INIT_TAKE1("Auth_MemCookie_Memcache_Servers", ap_set_string_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, szAuth_MemCookie_memCached_addr), OR_AUTHCFG, "Comma-separate list of memcached servers - hostname[:port][,hostname[:port]]"),
    AP_INIT_TAKE1("Auth_MemCookie_Memcache_Expiration", ap_set_int_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, tAuth_MemCookie_MemcacheObjectExpiry), OR_AUTHCFG, "Expiration time for sessions,in seconds."),
    AP_INIT_TAKE1("Auth_MemCookie_SessionTableSize", ap_set_int_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_SessionTableSize), OR_AUTHCFG, "Maximum number of concurrent sessions.  Defaults to 10."),
    AP_INIT_FLAG ("Auth_MemCookie_Memcached_ExpirationReset", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_MemcacheObjectExpiryReset), OR_AUTHCFG, "Reset expiration time of session on each request.  Defaults to 'yes'"),
    AP_INIT_FLAG ("Auth_MemCookie_SetSessionHTTPHeader", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_SetSessionHTTPHeader), OR_AUTHCFG, "Set to 'yes' to set session information to http header of the authenticated users, no by default"),
    AP_INIT_FLAG ("Auth_MemCookie_SetSessionHTTPHeaderEncode", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_SetSessionHTTPHeaderEncode), OR_AUTHCFG, "Set to 'yes' to mime64 encode session information to http header, no by default"),
    AP_INIT_TAKE1("Auth_MemCookie_CookieName", ap_set_string_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, szAuth_MemCookie_CookieName), OR_AUTHCFG, "The name of the cookie used for holding session information."),
    AP_INIT_TAKE1 ("Auth_MemCookie_MatchIPMode", cmd_MatchIP_Mode, NULL, OR_AUTHCFG, "Whether or not to check the IP associated with the session cookie on each request. Possible values: 0 -> disabled, 1 -> 'X-Forwarded-For' HTTP header, 2 -> 'Via' HTTP header, 3 -> Apache 'REMOTE_IP'."),
    AP_INIT_FLAG ("Auth_MemCookie_GroupAuthoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_GroupAuthoritative), OR_AUTHCFG, "Set to 'no' to allow access control to be passed along to lower modules, for group acl check, set to 'yes' by default."),
    AP_INIT_FLAG ("Auth_MemCookie_Authoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_Authoritative), OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default"),
    AP_INIT_FLAG ("Auth_MemCookie_SimulateBasicAuth", ap_set_flag_slot, (void *)APR_OFFSETOF(strAuth_MemCookie_config_rec, nAuth_MemCookie_authbasicfix), OR_AUTHCFG, "Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'yes' by default"),
    {NULL}
};

/* Define the structure of the module. */
module AP_MODULE_DECLARE_DATA mod_auth_memcookie_module =
{
    STANDARD20_MODULE_STUFF,
    Auth_MemCookie_CreateDefaultConfig, /* Creates a default config for the module. */
    NULL,                               /* Directory merger; default is override. */
    NULL,                               /* Server config. */
    NULL,                               /* Merge server config. */
    Auth_MemCookie_commandTable,        /* Our command (how to parse config values) table. */
    Auth_MemCookie_RegisterHooks        /* Register hooks. */
};
