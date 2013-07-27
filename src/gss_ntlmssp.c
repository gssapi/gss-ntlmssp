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
#include <time.h>

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

uint32_t gssntlm_context_is_valid(struct gssntlm_ctx *ctx, time_t *time_now)
{
    time_t now;

    if (!ctx->established) return GSS_S_NO_CONTEXT;

    now = time(NULL);
    if (now > ctx->expiration_time) return GSS_S_CONTEXT_EXPIRED;

    if (time_now) *time_now = now;
    return GSS_S_COMPLETE;
}

int gssntlm_get_lm_compatibility_level(void)
{
    const char *envvar;

    envvar = getenv("LM_COMPAT_LEVEL");
    if (envvar != NULL) {
        return atoi(envvar);
    }

    /* use the most secure setting by default */
    return SEC_LEVEL_MAX;
}
