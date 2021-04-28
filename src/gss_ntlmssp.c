/* Copyright 2013 Simo Sorce <simo@samba.org>, see COPYING for license */

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

uint32_t gssntlm_mech_invoke(uint32_t *minor_status,
                             const gss_OID desired_mech,
                             const gss_OID desired_object,
                             gss_buffer_t value)
{
    uint32_t retmaj = GSS_S_COMPLETE;
    uint32_t retmin = 0;

    if (minor_status == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (desired_mech != GSS_C_NO_OID &&
        !gss_oid_equal(desired_mech, &gssntlm_oid)) {
        return GSSERRS(0, GSS_S_BAD_MECH);
    }

    if (desired_object == GSS_C_NO_OID) {
        return GSSERRS(0, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (!gss_oid_equal(desired_object, &gssntlm_debug_oid)) {
        return GSSERRS(EINVAL, GSS_S_UNAVAILABLE);
    }

    retmin = gssntlm_debug_invoke(value);
    if (retmin != 0) {
        retmaj = GSS_S_UNAVAILABLE;
    }

    return GSSERR();
}
