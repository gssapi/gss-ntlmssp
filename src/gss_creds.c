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


static int get_initial_creds(struct gssntlm_name *name,
                             struct gssntlm_cred **creds)
{
    struct gssntlm_cred *cred = NULL;
    const char *envvar;
    char line[1024];
    char *dom, *usr, *pwd;
    char *p;
    bool found = false;
    FILE *f;
    int ret;

    /* use the same var used by Heimdal */
    envvar = getenv("NTLM_USER_FILE");
    if (envvar != NULL) {
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

            /* if no name is specified user the first found */
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

        if (found) {
            cred = calloc(1, sizeof(struct gssntlm_cred));
            if (!cred) return errno;

            cred->type = GSSNTLM_CRED_USER;
            cred->cred.user.user.type = GSSNTLM_NAME_USER;
            cred->cred.user.user.data.user.domain = strdup(dom);
            if (!cred->cred.user.user.data.user.domain) {
                ret = ENOMEM;
                goto done;
            }
            cred->cred.user.user.data.user.name = strdup(usr);
            if (!cred->cred.user.user.data.user.name) {
                ret = ENOMEM;
                goto done;
            }
            cred->cred.user.nt_hash.length = 16;

            ret = NTOWFv1(pwd, &cred->cred.user.nt_hash);
            if (ret) goto done;

            envvar = getenv("LM_COMPAT_LEVEL");
            if (envvar != NULL) {
                cred->lm_compatibility_level = atoi(envvar);
            } else {
                /* use most secure defaults for now, we can add options to
                 * relax security later */
                cred->lm_compatibility_level = SEC_LEVEL_MAX;
            }

            if (cred->lm_compatibility_level < 3) {
                cred->cred.user.lm_hash.length = 16;
                ret = LMOWFv1(pwd, &cred->cred.user.lm_hash);
            }
            goto done;
        }
    }

    ret = ENOENT;

done:
    if (ret) {
        gssntlm_int_release_cred(cred);
    } else {
        *creds = cred;
    }
    return ret;
}

static void gssntlm_copy_key(struct ntlm_key *dest, struct ntlm_key *src)
{
    memcpy(dest->data, src->data, src->length);
    dest->length = src->length;
}

int gssntlm_copy_creds(struct gssntlm_cred *in, struct gssntlm_cred *out)
{
    char *dom = NULL, *usr = NULL;
    int ret = 0;

    out->type = GSSNTLM_CRED_NONE;

    switch (in->type) {
    case GSSNTLM_CRED_NONE:
        break;
    case GSSNTLM_CRED_ANON:
        out->cred.anon.dummy = 1;
        break;
    case GSSNTLM_CRED_USER:
        dom = strdup(in->cred.user.user.data.user.domain);
        if (!dom) {
            ret = ENOMEM;
            goto done;
        }
        usr = strdup(in->cred.user.user.data.user.name);
        if (!usr) {
            ret = ENOMEM;
            goto done;
        }
        out->cred.user.user.data.user.domain = dom;
        out->cred.user.user.data.user.name = usr;
        gssntlm_copy_key(&out->cred.user.nt_hash,
                         &in->cred.user.nt_hash);
        gssntlm_copy_key(&out->cred.user.lm_hash,
                         &in->cred.user.lm_hash);
        break;
    case GSSNTLM_CRED_SERVER:
        out->cred.server.dummy = 1;
        break;
    }
    out->type = in->type;

    out->lm_compatibility_level = in->lm_compatibility_level;

done:
    if (ret) {
        safefree(dom);
        safefree(usr);
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
        safefree(cred->cred.user.user.data.user.domain);
        safefree(cred->cred.user.user.data.user.name);
        safezero(cred->cred.user.nt_hash.data, 16);
        cred->cred.user.nt_hash.length = 0;
        safezero(cred->cred.user.lm_hash.data, 16);
        cred->cred.user.lm_hash.length = 0;
        break;
    case GSSNTLM_CRED_SERVER:
        cred->cred.server.dummy = 0;
        break;
    }
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
    struct gssntlm_cred *cred;
    struct gssntlm_name *name;
    uint32_t retmaj = GSS_S_COMPLETE;
    uint32_t retmin = 0;

    name = (struct gssntlm_name *)desired_name;

    if (cred_usage == GSS_C_BOTH || cred_usage == GSS_C_INITIATE) {
        if (name != NULL && name->type != GSSNTLM_NAME_USER) {
            retmin = EINVAL;
            retmaj = GSS_S_CRED_UNAVAIL;
            goto done;
        }

        retmin = get_initial_creds(name, &cred);
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

uint32_t gssntlm_release_cred(uint32_t *minor_status,
                              gss_cred_id_t *cred_handle)
{
    *minor_status = 0;

    if (!cred_handle) return GSS_S_COMPLETE;

    gssntlm_int_release_cred((struct gssntlm_cred *)*cred_handle);
    safefree(*cred_handle);

    return GSS_S_COMPLETE;
}

