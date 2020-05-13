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

#include "gssapi_ntlmssp.h"
#include "gss_ntlmssp.h"

#define SEC_LEVEL_MIN 0
#define SEC_LEVEL_MAX 5

#define SEC_LM_OK 0x01
#define SEC_NTLM_OK 0x02
#define SEC_EXT_SEC_OK 0x04
#define SEC_V2_OK 0x08
#define SEC_DC_LM_OK 0x10
#define SEC_DC_NTLM_OK 0x20
#define SEC_DC_V2_OK 0x40

const gss_OID_desc gssntlm_oid = {
    .length = GSS_NTLMSSP_OID_LENGTH,
    .elements = discard_const(GSS_NTLMSSP_OID_STRING)
};

bool gssntlm_required_security(int security_level, struct gssntlm_ctx *ctx)
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
        resp |= SEC_V2_OK | SEC_EXT_SEC_OK;
        break;
    case 4:
        if (ctx->role == GSSNTLM_DOMAIN_CONTROLLER) resp &= ~SEC_DC_LM_OK;
        resp |= SEC_V2_OK | SEC_EXT_SEC_OK;
        break;
    case 5:
        if (ctx->role == GSSNTLM_DOMAIN_CONTROLLER) resp = SEC_DC_V2_OK;
        resp |= SEC_V2_OK | SEC_EXT_SEC_OK;
        break;
    default:
        return false;
    }

    ctx->sec_req = resp;
    return true;
}

void gssntlm_set_role(struct gssntlm_ctx *ctx,
                      int desired, char *nb_domain_name)
{
    if (desired == GSSNTLM_CLIENT) {
        ctx->role = GSSNTLM_CLIENT;
    } else if (nb_domain_name && *nb_domain_name &&
               strcmp(nb_domain_name, DEF_NB_DOMAIN) != 0) {
        ctx->role = GSSNTLM_DOMAIN_SERVER;
    } else {
        ctx->role = GSSNTLM_SERVER;
    }
}

bool gssntlm_role_is_client(struct gssntlm_ctx *ctx)
{
    return (ctx->role == GSSNTLM_CLIENT);
}

bool gssntlm_role_is_server(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_SERVER:
    case GSSNTLM_DOMAIN_SERVER:
    case GSSNTLM_DOMAIN_CONTROLLER:
        return true;
    default:
        break;
    }
    return false;
}

bool gssntlm_role_is_domain_member(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_DOMAIN_SERVER:
    case GSSNTLM_DOMAIN_CONTROLLER:
        return true;
    default:
        break;
    }
    return false;
}

bool gssntlm_sec_lm_ok(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_CLIENT:
    case GSSNTLM_SERVER:
        return (ctx->sec_req & SEC_LM_OK);
    case GSSNTLM_DOMAIN_SERVER:
        return true; /* defer decision to DC */
    case GSSNTLM_DOMAIN_CONTROLLER:
        return (ctx->sec_req & SEC_DC_LM_OK);
    }
    return false;
}

bool gssntlm_sec_ntlm_ok(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_CLIENT:
    case GSSNTLM_SERVER:
        return (ctx->sec_req & SEC_NTLM_OK);
    case GSSNTLM_DOMAIN_SERVER:
        return true; /* defer decision to DC */
    case GSSNTLM_DOMAIN_CONTROLLER:
        return (ctx->sec_req & SEC_DC_NTLM_OK);
    }
    return false;
}

bool gssntlm_sec_v2_ok(struct gssntlm_ctx *ctx)
{
    switch (ctx->role) {
    case GSSNTLM_CLIENT:
    case GSSNTLM_SERVER:
        return (ctx->sec_req & SEC_V2_OK);
    case GSSNTLM_DOMAIN_SERVER:
        return true; /* defer decision to DC */
    case GSSNTLM_DOMAIN_CONTROLLER:
        return (ctx->sec_req & SEC_DC_V2_OK);
    }
    return false;
}

bool gssntlm_ext_sec_ok(struct gssntlm_ctx *ctx)
{
    return (ctx->sec_req & SEC_EXT_SEC_OK);
}

uint32_t gssntlm_context_is_valid(struct gssntlm_ctx *ctx, time_t *time_now)
{
    time_t now;

    if (!ctx) return GSS_S_NO_CONTEXT;
    if (!(ctx->int_flags & NTLMSSP_CTX_FLAG_ESTABLISHED)) {
        return GSS_S_NO_CONTEXT;
    }

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

    /* use 3 by default for better compatibility */
    return 3;
}
