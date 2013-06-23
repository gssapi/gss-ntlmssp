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
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "gss_ntlmssp.h"

/* 1.3.6.1.4.1.311.2.2.10 */
const gss_OID_desc gssntlm_oid = {
    .length = 10,
    .elements = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
};

uint8_t gssntlm_required_security(int security_level,
                                  enum gssntlm_role role)
{
    uint8_t resp;

    /* DC defaults */
    resp = SEC_DC_LM_OK | SEC_DC_NTLM_OK | SEC_DC_V2_OK;

    switch (security_level) {
    case 0:
        resp |= SEC_LM_OK | SEC_NTLM_OK;
        break;
    case 1:
        resp |= SEC_LM_OK | SEC_NTLM_OK | SEC_EXT_SEC_OK;
        break;
    case 2:
        resp |= SEC_NTLM_OK | SEC_EXT_SEC_OK;
        break;
    case 3:
        resp |= SEC_V2_ONLY | SEC_EXT_SEC_OK;
        break;
    case 4:
        resp |= SEC_NTLM_OK | SEC_EXT_SEC_OK;
        if (role == GSSNTLM_DOMAIN_CONTROLLER) resp &= ~SEC_DC_LM_OK;
        break;
    case 5:
        if (role == GSSNTLM_DOMAIN_CONTROLLER) resp = SEC_DC_V2_OK;
        resp |= SEC_V2_ONLY | SEC_EXT_SEC_OK;
        break;
    default:
        resp = 0xff;
        break;
    }

    return resp;
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
        break;
    case GSSNTLM_CRED_SERVER:
        out->cred.server.dummy = 1;
        break;
    }

    out->type = in->type;

done:
    if (ret) {
        safefree(dom);
        safefree(usr);
    }
    return ret;
}

void gssntlm_int_release_cred(struct gssntlm_cred *cred)
{
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
    /* FIXME: Fecth creds from somewhere */
    *minor_status = 0;
    return GSS_S_CRED_UNAVAIL;
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

