/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include "config.h"
#include <errno.h>
#include "gss_ntlmssp.h"

#if HAVE_WBCLIENT
#include "gss_ntlmssp_winbind.h"
#endif

void *external_get_context(void)
{
#if HAVE_WBCLIENT
    return winbind_get_context();
#else
    return NULL;
#endif
}

void external_free_context(void *ctx)
{
#if HAVE_WBCLIENT
    winbind_free_context(ctx);
#else
    return;
#endif
}

uint32_t external_netbios_get_names(void *ctx, char **computer, char **domain)
{
#if HAVE_WBCLIENT
    return winbind_get_names(ctx, computer, domain);
#else
    return ERR_NOTAVAIL;
#endif
}

uint32_t external_get_creds(void *ctx,
                            struct gssntlm_name *name,
                            struct gssntlm_cred *cred)
{
    void *ectx = NULL;
    uint32_t ret;

    if (ctx == NULL) {
        ectx = external_get_context();
    } else {
        ectx = ctx;
    }
#if HAVE_WBCLIENT
    ret = winbind_get_creds(ectx, name, cred);
#else
    ret = ERR_NOTAVAIL;
#endif
    if (ctx == NULL) {
        external_free_context(ectx);
    }
    return ret;
}

uint32_t external_cli_auth(struct gssntlm_ctx *ctx,
                           struct gssntlm_cred *cred,
                           uint32_t in_flags,
                           gss_channel_bindings_t input_chan_bindings)
{
#if HAVE_WBCLIENT
    return winbind_cli_auth(ctx->external_context,
                            cred->cred.external.user.data.user.name,
                            cred->cred.external.user.data.user.domain,
                            input_chan_bindings,
                            in_flags, &ctx->neg_flags,
                            &ctx->nego_msg, &ctx->chal_msg, &ctx->auth_msg,
                            &ctx->exported_session_key);
#else
    return ERR_NOTAVAIL;
#endif
}

uint32_t external_srv_auth(struct gssntlm_ctx *ctx,
                           struct gssntlm_cred *cred,
                           struct ntlm_buffer *nt_chal_resp,
                           struct ntlm_buffer *lm_chal_resp,
                           struct ntlm_key *session_base_key)
{
#if HAVE_WBCLIENT
    uint8_t challenge[8];
    uint8_t *chal_ptr;

    /* NOTE: in the ntlmv1 extended security case, winbindd wants a
     * pre-digested challenge, this is arguably a bug as it has all
     * the data needed to compute it by itself ... just cope */
    if (is_ntlm_v1(nt_chal_resp) &&
        (ctx->neg_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) ) {
        int ret;

        ret = ntlm_compute_ext_sec_challenge(ctx->server_chal,
                                             lm_chal_resp->data,
                                             challenge);
        if (ret) return ret;
        chal_ptr = challenge;
    } else {
        chal_ptr = ctx->server_chal;
    }

    return winbind_srv_auth(ctx->external_context,
                            cred->cred.external.user.data.user.name,
                            cred->cred.external.user.data.user.domain,
                            ctx->workstation, chal_ptr,
                            nt_chal_resp, lm_chal_resp, session_base_key,
                            &ctx->source_name.attrs);
#else
    return ERR_NOTAVAIL;
#endif
}
