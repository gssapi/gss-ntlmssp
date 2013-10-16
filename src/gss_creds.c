/*
   Copyright (C) 2013 Simo Sorce <simo@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "gss_ntlmssp.h"

static int get_user_file_creds(struct gssntlm_name *name,
                               struct gssntlm_cred *cred)
{
    const char *envvar;
    char line[1024];
    char *dom, *usr, *pwd;
    char *p;
    bool found = false;
    FILE *f;
    int ret;

    /* use the same var used by Heimdal */
    envvar = getenv("NTLM_USER_FILE");
    if (envvar == NULL) return ENOENT;

    /* Use the same file format used by Heimdal in hope to achieve
     * some compatibility between implementations:
     * Each line is one entry like the following:
     * DOMAIN:USERNAME:PASSWORD */
    f = fopen(envvar, "r");
    if (!f) return errno;

    while(fgets(line, 1024, f)) {
        p = line;
        if (*p == '#') continue;
        dom = p;
        p = strchr(dom, ':');
        if (!p) continue;
        *p++ = '\0';
        usr = p;
        p = strchr(usr, ':');
        if (!p) continue;
        *p++ = '\0';
        pwd = p;
        strsep(&p, "\r\n");

        /* if no name is specified use the first found */
        if (name == NULL) {
            found = true;
            break;
        }

        if (name->data.user.domain) {
            if (!ntlm_casecmp(dom, name->data.user.domain)) continue;
        }
        if (name->data.user.name) {
            if (!ntlm_casecmp(usr, name->data.user.name)) continue;
        }
        /* all matched (NULLs in name are wildcards) */
        found = true;
        break;
    }

    fclose(f);

    if (!found) {
        return ENOENT;
    }

    cred->type = GSSNTLM_CRED_USER;
    cred->cred.user.user.type = GSSNTLM_NAME_USER;
    cred->cred.user.user.data.user.domain = strdup(dom);
    if (!cred->cred.user.user.data.user.domain) return ENOMEM;
    cred->cred.user.user.data.user.name = strdup(usr);
    if (!cred->cred.user.user.data.user.name) return ENOMEM;
    cred->cred.user.nt_hash.length = 16;

    ret = NTOWFv1(pwd, &cred->cred.user.nt_hash);
    if (ret) return ret;

    if (gssntlm_get_lm_compatibility_level() < 3) {
        cred->cred.user.lm_hash.length = 16;
        ret = LMOWFv1(pwd, &cred->cred.user.lm_hash);
        if (ret) return ret;
    }

    return 0;
}

static int get_server_creds(struct gssntlm_name *name,
                            struct gssntlm_cred *cred)
{
    if (!name) return EINVAL;
    cred->type = GSSNTLM_CRED_SERVER;
    return gssntlm_copy_name(name, &cred->cred.server.name);
}

static int hex_to_key(const char *hex, struct ntlm_key *key)
{
    const char *p;
    uint32_t i, j;
    uint8_t t;
    size_t len;

    len = strlen(hex);
    if (len != 32) return EINVAL;

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 2; j++) {
            p = &hex[j + (i * 2)];
            if (*p >= '0' && *p <= '9') {
                t = (*p - '0');
            } else if (*p >= 'A' && *p <= 'F') {
                t = (*p - 'A' + 10);
            } else {
                return EINVAL;
            }
            if (j == 0) t = t << 4;
            key->data[i] = t;
        }
    }
    key->length = 16;
    return 0;
}

#define NTLM_CS_DOMAIN "ntlm:domain"
#define NTLM_CS_NTHASH "ntlm:nthash"
#define NTLM_CS_PASSWORD "ntlm:password"
#define GENERIC_CS_PASSWORD "password"
/* To support in future, RC4 Key is NT hash */
#define KRB5_CS_CLI_KEYTAB_URN "client_keytab"
#define KRB5_CS_KEYTAB_URN "keytab"

static int get_creds_from_store(struct gssntlm_name *name,
                                struct gssntlm_cred *cred,
                                gss_const_key_value_set_t cred_store)
{
    uint32_t i;
    int ret;

    cred->type = GSSNTLM_CRED_NONE;

    if (name) {
        switch (name->type) {
        case GSSNTLM_NAME_NULL:
            cred->type = GSSNTLM_CRED_NONE;
            break;
        case GSSNTLM_NAME_ANON:
            cred->type = GSSNTLM_CRED_ANON;
            break;
        case GSSNTLM_NAME_USER:
            cred->type = GSSNTLM_CRED_USER;
            ret = gssntlm_copy_name(name, &cred->cred.user.user);
            break;
        case GSSNTLM_NAME_SERVER:
            cred->type = GSSNTLM_CRED_SERVER;
            ret = gssntlm_copy_name(name, &cred->cred.server.name);
            break;
        default:
            return EINVAL;
        }
    }

    /* so far only user options can be defined in the cred_store */
    if (cred->type != GSSNTLM_CRED_USER) return 0;

    for (i = 0; i < cred_store->count; i++) {
        if (strcmp(cred_store->elements[i].key, NTLM_CS_DOMAIN) == 0) {
            /* ignore duplicates */
            if (cred->cred.user.user.data.user.domain) continue;
            cred->cred.user.user.data.user.domain =
                                    strdup(cred_store->elements[i].value);
            if (!cred->cred.user.user.data.user.domain) return ENOMEM;
        }
        if (strcmp(cred_store->elements[i].key, NTLM_CS_NTHASH) == 0) {
            /* ignore duplicates */
            if (cred->cred.user.nt_hash.length) continue;
            ret = hex_to_key(cred_store->elements[i].value,
                             &cred->cred.user.nt_hash);
            if (ret) return ret;
        }
        if ((strcmp(cred_store->elements[i].key, NTLM_CS_PASSWORD) == 0) ||
            (strcmp(cred_store->elements[i].key, GENERIC_CS_PASSWORD) == 0)) {
            if (cred->cred.user.nt_hash.length) continue;
            cred->cred.user.nt_hash.length = 16;
            ret = NTOWFv1(cred_store->elements[i].value,
                          &cred->cred.user.nt_hash);
            if (ret) return ret;
        }
    }

    /* TODO: should we call get_user_file_creds/get_server_creds if values are
     * not found ?
     */

    return 0;
}

static void gssntlm_copy_key(struct ntlm_key *dest, struct ntlm_key *src)
{
    memcpy(dest->data, src->data, src->length);
    dest->length = src->length;
}

int gssntlm_copy_creds(struct gssntlm_cred *in, struct gssntlm_cred *out)
{
    char *dom = NULL, *usr = NULL, *srv = NULL;
    int ret = 0;

    out->type = GSSNTLM_CRED_NONE;

    switch (in->type) {
    case GSSNTLM_CRED_NONE:
        break;
    case GSSNTLM_CRED_ANON:
        out->cred.anon.dummy = 1;
        break;
    case GSSNTLM_CRED_USER:
        ret = gssntlm_copy_name(&in->cred.user.user,
                                &out->cred.user.user);
        if (ret) goto done;
        gssntlm_copy_key(&out->cred.user.nt_hash,
                         &in->cred.user.nt_hash);
        gssntlm_copy_key(&out->cred.user.lm_hash,
                         &in->cred.user.lm_hash);
        break;
    case GSSNTLM_CRED_SERVER:
        ret = gssntlm_copy_name(&in->cred.server.name,
                                &out->cred.server.name);
        if (ret) goto done;
        break;
    }
    out->type = in->type;

done:
    if (ret) {
        safefree(dom);
        safefree(usr);
        safefree(srv);
    }
    return ret;
}

void gssntlm_int_release_cred(struct gssntlm_cred *cred)
{
    if (!cred) return;

    switch (cred->type) {
    case GSSNTLM_CRED_NONE:
        break;
    case GSSNTLM_CRED_ANON:
        cred->cred.anon.dummy = 0;
        break;
    case GSSNTLM_CRED_USER:
        gssntlm_int_release_name(&cred->cred.user.user);
        safezero(cred->cred.user.nt_hash.data, 16);
        cred->cred.user.nt_hash.length = 0;
        safezero(cred->cred.user.lm_hash.data, 16);
        cred->cred.user.lm_hash.length = 0;
        break;
    case GSSNTLM_CRED_SERVER:
        gssntlm_int_release_name(&cred->cred.server.name);
        break;
    }
}

uint32_t gssntlm_acquire_cred_from(uint32_t *minor_status,
                                   gss_name_t desired_name,
                                   uint32_t time_req,
                                   gss_OID_set desired_mechs,
                                   gss_cred_usage_t cred_usage,
                                   gss_const_key_value_set_t cred_store,
                                   gss_cred_id_t *output_cred_handle,
                                   gss_OID_set *actual_mechs,
                                   uint32_t *time_rec)
{
    struct gssntlm_cred *cred;
    struct gssntlm_name *name;
    uint32_t retmaj = GSS_S_COMPLETE;
    uint32_t retmin = 0;

    name = (struct gssntlm_name *)desired_name;

    cred = calloc(1, sizeof(struct gssntlm_cred));
    if (!cred) {
        retmin = errno;
        return GSS_S_FAILURE;
    }

    /* FIXME: should we split the cred union and allow GSS_C_BOTH ?
     * It may be possible to specify get server name from env and/or
     * user creds from cred store at the same time, etc .. */
    if (cred_usage == GSS_C_BOTH) {
        if (name->type == GSSNTLM_NAME_USER ||
            name->type == GSSNTLM_NAME_ANON) {
            cred_usage = GSS_C_INITIATE;
        }
        if (name->type == GSSNTLM_NAME_SERVER) {
            cred_usage = GSS_C_ACCEPT;
        }
    }

    if (cred_usage == GSS_C_INITIATE) {
        if (name != NULL && name->type != GSSNTLM_NAME_USER) {
            retmin = EINVAL;
            retmaj = GSS_S_CRED_UNAVAIL;
            goto done;
        }

        if (cred_store != GSS_C_NO_CRED_STORE) {
            retmin = get_creds_from_store(name, cred, cred_store);
        } else {
            retmin = get_user_file_creds(name, cred);
        }
        if (retmin) {
            retmaj = GSS_S_CRED_UNAVAIL;
        }
    } else if (cred_usage == GSS_C_ACCEPT) {
        if (name != NULL && name->type != GSSNTLM_NAME_SERVER) {
            retmin = EINVAL;
            retmaj = GSS_S_CRED_UNAVAIL;
            goto done;
        }

        if (cred_store != GSS_C_NO_CRED_STORE) {
            retmin = get_creds_from_store(name, cred, cred_store);
        } else {
            retmin = get_server_creds(name, cred);
        }
        if (retmin) {
            retmaj = GSS_S_CRED_UNAVAIL;
        }
    } else {
        retmin = EINVAL;
        retmaj = GSS_S_CRED_UNAVAIL;
    }

done:
    if (retmaj) {
        uint32_t tmpmin;
        gssntlm_release_cred(&tmpmin, (gss_cred_id_t *)&cred);
    } else {
        *output_cred_handle = (gss_cred_id_t)cred;
    }
    *minor_status = retmin;
    return retmaj;
}

uint32_t gssntlm_acquire_cred(uint32_t *minor_status,
                              gss_name_t desired_name,
                              uint32_t time_req,
                              gss_OID_set desired_mechs,
                              gss_cred_usage_t cred_usage,
                              gss_cred_id_t *output_cred_handle,
                              gss_OID_set *actual_mechs,
                              uint32_t *time_rec)
{
    return gssntlm_acquire_cred_from(minor_status,
                                     desired_name,
                                     time_req,
                                     desired_mechs,
                                     cred_usage,
                                     GSS_C_NO_CRED_STORE,
                                     output_cred_handle,
                                     actual_mechs,
                                     time_rec);
}

uint32_t gssntlm_release_cred(uint32_t *minor_status,
                              gss_cred_id_t *cred_handle)
{
    *minor_status = 0;

    if (!cred_handle) return GSS_S_COMPLETE;

    gssntlm_int_release_cred((struct gssntlm_cred *)*cred_handle);
    safefree(*cred_handle);

    return GSS_S_COMPLETE;
}

