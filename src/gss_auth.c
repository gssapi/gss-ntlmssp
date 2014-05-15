/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include <errno.h>
#include "gss_ntlmssp.h"

uint32_t gssntlm_srv_auth(uint32_t *minor,
                          struct gssntlm_ctx *ctx,
                          struct gssntlm_cred *cred,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *key_exchange_key)
{
    struct ntlm_key ntlmv2_key = { .length = 16 };
    struct ntlm_buffer nt_proof = { 0 };
    uint32_t retmaj, retmin;
    const char *domstr;
    int retries;

    if (key_exchange_key->length != 16) {
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    switch (cred->type) {

    case GSSNTLM_CRED_USER:
        for (retries = 2; retries > 0; retries--) {

            if (retries == 2) {
                domstr = cred->cred.user.user.data.user.domain;
            } else {
                domstr = NULL;
            }

            /* NTLMv2 Key */
            retmin = NTOWFv2(ctx->ntlm, &cred->cred.user.nt_hash,
                             cred->cred.user.user.data.user.name,
                             domstr, &ntlmv2_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Response */
            retmin = ntlmv2_verify_nt_response(nt_chal_resp,
                                               &ntlmv2_key,
                                               ctx->server_chal);
            if (retmin == 0) {
                break;
            } else {
                if (ctx->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) {
                    /* LMv2 Response */
                    retmin = ntlmv2_verify_lm_response(lm_chal_resp,
                                                       &ntlmv2_key,
                                                       ctx->server_chal);
                    if (retmin == 0) {
                        break;
                    }
                }
            }
            if (retmin && retries < 2) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        }
        /* The NT proof is the first 16 bytes */
        nt_proof.data = nt_chal_resp->data;
        nt_proof.length = 16;

        /* The Session Base Key */
        /* In NTLMv2 the Key Exchange Key is the Session Base Key */
        retmin = ntlmv2_session_base_key(&ntlmv2_key, &nt_proof,
                                     key_exchange_key);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        break;

    case GSSNTLM_CRED_EXTERNAL:
        retmin = external_srv_auth(cred->cred.external.user.data.user.name,
                                   cred->cred.external.user.data.user.domain,
                                   ctx->workstation, ctx->server_chal,
                                   nt_chal_resp, lm_chal_resp,
                                   key_exchange_key);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        break;

    default:
        retmin = EINVAL;
        retmaj = GSS_S_FAILURE;
        goto done;
    }

    retmaj = GSS_S_COMPLETE;
    retmin = 0;

done:
    *minor = retmin;
    return retmaj;
}
