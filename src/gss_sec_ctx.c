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


uint32_t gssntlm_init_sec_context(uint32_t *minor_status,
                                  gss_cred_id_t claimant_cred_handle,
                                  gss_ctx_id_t *context_handle,
                                  gss_name_t target_name,
                                  gss_OID mech_type,
                                  uint32_t req_flags,
                                  uint32_t time_req,
                                  gss_channel_bindings_t input_chan_bindings,
                                  gss_buffer_t input_token,
                                  gss_OID *actual_mech_type,
                                  gss_buffer_t output_token,
                                  uint32_t *ret_flags,
                                  uint32_t *time_rec)
{
    struct gssntlm_ctx *ctx;
    struct gssntlm_name *server = NULL;
    struct gssntlm_cred *cred = NULL;
    const char *workstation = NULL;
    const char *domain = NULL;
    uint32_t in_flags;
    uint32_t msg_type;
    char *trgt_name;
    uint8_t server_chal[8];
    struct ntlm_buffer challenge = { server_chal, 8 };
    struct ntlm_buffer target_info = { 0 };
    char *trginfo_name = NULL;
    uint64_t srv_time = 0;
    struct ntlm_buffer nt_chal_resp = { 0 };
    struct ntlm_buffer lm_chal_resp = { 0 };
    struct ntlm_buffer enc_sess_key = { 0 };
    struct ntlm_key encrypted_random_session_key = { .length = 16 };
    struct ntlm_key key_exchange_key = { .length = 16 };
    uint32_t tmpmin;
    uint32_t retmin = 0;
    uint32_t retmaj = 0;
    uint8_t sec_req;
    bool key_exch;

    /* reset return values */
    *minor_status = 0;
    if (actual_mech_type) *actual_mech_type = NULL;
    if (ret_flags) *ret_flags = 0;
    if (time_rec) *time_rec = 0;

    if (target_name) {
        server = (struct gssntlm_name *)target_name;
        if (server->type != GSSNTLM_NAME_SERVER) {
            return GSS_S_BAD_NAMETYPE;
        }
        if (!server->data.server.name ||
            !server->data.server.name[0]) {
            return GSS_S_BAD_NAME;
        }
    }

    if (*context_handle == GSS_C_NO_CONTEXT) {

        if (input_token && input_token->length != 0) {
            return GSS_S_DEFECTIVE_TOKEN;
        }

        /* first call */
        ctx = calloc(1, sizeof(struct gssntlm_ctx));
        if (!ctx) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
            if (req_flags & GSS_C_ANON_FLAG) {
                ctx->cred.type = GSSNTLM_CRED_ANON;
                ctx->cred.cred.anon.dummy = 1;
            } else {
                retmaj = gssntlm_acquire_cred(&retmin,
                                               NULL, time_req,
                                               NULL, GSS_C_INITIATE,
                                               (gss_cred_id_t *)&cred,
                                               NULL, time_rec);
                if (retmaj) goto done;
            }
        } else {
            cred = (struct gssntlm_cred *)claimant_cred_handle;
        }

        retmin = gssntlm_copy_creds(cred, &ctx->cred);
        if (retmin != 0) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->gss_flags = req_flags;

        ctx->role = GSSNTLM_CLIENT;

        ctx->neg_flags = NTLMSSP_DEFAULT_CLIENT_FLAGS;

        /*
         * we ignore unsupported flags for now
         *
         * GSS_C_DELEG_FLAG
         * GSS_C_MUTUAL_FLAG
         * GSS_C_PROT_READY_FLAG
         * GSS_C_TRANS_FLAG
         * GSS_C_DELEG_POLICY_FLAG
         * GSS_C_DCE_STYLE
         * GSS_C_EXTENDED_ERROR_FLAG
         */
        if ((req_flags & GSS_C_INTEG_FLAG) ||
            (req_flags & GSS_C_REPLAY_FLAG) ||
            (req_flags & GSS_C_SEQUENCE_FLAG)) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
        }
        if (req_flags & GSS_C_CONF_FLAG) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_SEAL |
                              NTLMSSP_NEGOTIATE_KEY_EXCH |
                              NTLMSSP_NEGOTIATE_LM_KEY |
                              NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }
        if (req_flags & GSS_C_ANON_FLAG) {
            ctx->neg_flags |= NTLMSSP_ANONYMOUS;
        }
        if (req_flags & GSS_C_IDENTIFY_FLAG) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_IDENTIFY;
        }

        if (ctx->cred.type == GSSNTLM_CRED_USER &&
                ctx->cred.cred.user.user.data.user.domain) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
            domain = ctx->cred.cred.user.user.data.user.domain;
        }
        if (ctx->workstation) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
            workstation = ctx->workstation;
        }

        sec_req = gssntlm_required_security(cred->lm_compatibility_level,
                                            ctx->role);
        if (sec_req == 0xff) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        if (!(sec_req & SEC_LM_OK)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
        }
        if (!(sec_req & SEC_EXT_SEC_OK)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        retmin = ntlm_init_ctx(&ctx->ntlm);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        retmin = ntlm_encode_neg_msg(ctx->ntlm, ctx->neg_flags,
                                     domain, workstation, &ctx->nego_msg);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->stage = NTLMSSP_STAGE_NEGOTIATE;

        output_token->value = malloc(ctx->nego_msg.length);
        if (!output_token->value) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(output_token->value, ctx->nego_msg.data, ctx->nego_msg.length);
        output_token->length = ctx->nego_msg.length;

        retmaj = GSS_S_CONTINUE_NEEDED;

    } else {
        ctx = (struct gssntlm_ctx *)(*context_handle);

        if (ctx->role != GSSNTLM_CLIENT) {
            retmaj = GSS_S_NO_CONTEXT;
            goto done;
        }

        ctx->chal_msg.data = malloc(input_token->length);
        if (!ctx->chal_msg.data) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(ctx->chal_msg.data, input_token->value, input_token->length);
        ctx->chal_msg.length = input_token->length;

        retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->chal_msg, &msg_type);
        if (retmin) {
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        if (msg_type != NTLMSSP_STAGE_CHALLENGE ||
                ctx->stage != NTLMSSP_STAGE_NEGOTIATE) {
            retmaj = GSS_S_NO_CONTEXT;
            goto done;
        }

        retmin = ntlm_decode_chal_msg(ctx->ntlm, &ctx->chal_msg, &in_flags,
                                      &trgt_name, &challenge, &target_info);
        if (retmin) {
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        sec_req = gssntlm_required_security(ctx->cred.lm_compatibility_level,
                                            ctx->role);
        if (sec_req == 0xff) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        /* mask unacceptable flags */
        if (!(sec_req & SEC_LM_OK)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
        }
        if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_56)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_56;
        }
        if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_128)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_128;
        }
        if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_KEY_EXCH;
        }
        if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_OEM)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_OEM;
        }
        if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
            in_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
        }

        /* check required flags */
        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) &&
            (!(in_flags & NTLMSSP_NEGOTIATE_SEAL))) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) &&
            (!(in_flags & NTLMSSP_NEGOTIATE_SIGN))) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (!(in_flags & (NTLMSSP_NEGOTIATE_OEM |
                          NTLMSSP_NEGOTIATE_UNICODE))) {
            /* no common understanding */
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (ctx->gss_flags & GSS_C_ANON_FLAG) {
            /* Anonymous auth, empty responses */
            memset(&nt_chal_resp, 0, sizeof(nt_chal_resp));
            lm_chal_resp.data = malloc(1);
            if (!lm_chal_resp.data) {
                retmin = ENOMEM;
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            lm_chal_resp.data[0] = 0;
            lm_chal_resp.length = 1;

        } else if (sec_req & SEC_V2_ONLY) {

            /* ### NTLMv2 ### */
            uint8_t client_chal[8];
            struct ntlm_buffer cli_chal = { client_chal, 8 };
            struct ntlm_key ntlmv2_key = { .length = 16 };
            struct ntlm_buffer nt_proof = { 0 };

            if (target_info.length == 0) {
                retmaj = GSS_S_DEFECTIVE_TOKEN;
                goto done;
            }

            /* TODO: check that returned netbios/dns names match ? */
            /* TODO: support SingleHost and ChannelBindings buffers */
            /* NOTE: target_info should be re-encoded in the client to
             * augment it with correct client av_flags, but we skip that
             * for now, this means we never set the MIC flag either */
            retmin = ntlm_decode_target_info(ctx->ntlm, &target_info,
                                             NULL, NULL, NULL, NULL, NULL,
                                             &trginfo_name, NULL,
                                             &srv_time, NULL, NULL);
            if (retmin) {
                if (retmin == ERR_DECODE) {
                    retmaj = GSS_S_DEFECTIVE_TOKEN;
                } else {
                    retmaj = GSS_S_FAILURE;
                }
                goto done;
            }

            if (server && trginfo_name) {
                if (strcasecmp(server->data.server.name, trginfo_name) != 0) {
                    retmin = EINVAL;
                    retmaj = GSS_S_FAILURE;
                    goto done;
                }
            }

            /* the server did not send the timestamp, use current time */
            if (srv_time == 0) {
                srv_time = ntlm_timestamp_now();
            }

            /* Random client challenge */
            retmin = RAND_BUFFER(&cli_chal);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Key */
            retmin = NTOWFv2(ctx->ntlm, &ctx->cred.cred.user.nt_hash,
                             ctx->cred.cred.user.user.data.user.name,
                             ctx->cred.cred.user.user.data.user.domain,
                             &ntlmv2_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Response */
            retmin = ntlmv2_compute_nt_response(&ntlmv2_key,
                                                server_chal, client_chal,
                                                srv_time, &target_info,
                                                &nt_chal_resp);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* LMv2 Response */
            retmin = ntlmv2_compute_lm_response(&ntlmv2_key,
                                                server_chal, client_chal,
                                                &lm_chal_resp);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* The NT proof is the first 16 bytes */
            nt_proof.data = nt_chal_resp.data;
            nt_proof.length = 16;

            /* The Session Base Key */
            /* In NTLMv2 the Key Exchange Key is the Session Base Key */
            retmin = ntlmv2_session_base_key(&ntlmv2_key, &nt_proof,
                                             &key_exchange_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        } else {
            /* ### NTLMv1 ### */
            uint8_t client_chal[8];
            uint8_t nt_resp_buf[24];
            uint8_t lm_resp_buf[24];
            struct ntlm_buffer cli_chal = { client_chal, 8 };
            struct ntlm_buffer nt_response = { nt_resp_buf, 24 };
            struct ntlm_buffer lm_response = { lm_resp_buf, 24 };
            struct ntlm_key session_base_key = { .length = 16 };
            bool NoLMResponseNTLMv1 = true; /* FIXME: get from conf/env */
            bool ext_sec;

            /* Random client challenge */
            retmin = RAND_BUFFER(&cli_chal);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            ext_sec = (in_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);

            retmin = ntlm_compute_nt_response(&ctx->cred.cred.user.nt_hash,
                                              ext_sec, server_chal,
                                              client_chal, &nt_response);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            if (!ext_sec && NoLMResponseNTLMv1) {
                memcpy(lm_response.data, nt_response.data, 24);
            } else {
                retmin = ntlm_compute_lm_response(&ctx->cred.cred.user.lm_hash,
                                                  ext_sec, server_chal,
                                                  client_chal, &lm_response);
                if (retmin) {
                    retmaj = GSS_S_FAILURE;
                    goto done;
                }
            }

            retmin = ntlm_session_base_key(&ctx->cred.cred.user.nt_hash,
                                           &session_base_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            retmin = KXKEY(ctx->ntlm, ext_sec,
                           (in_flags & NTLMSSP_NEGOTIATE_LM_KEY),
                           (in_flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY),
                           server_chal, &ctx->cred.cred.user.lm_hash,
                           &session_base_key, &lm_response, &key_exchange_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        }

        key_exch = (in_flags & NTLMSSP_NEGOTIATE_KEY_EXCH);

        retmin = ntlm_exported_session_key(&key_exchange_key, key_exch,
                                           &ctx->exported_session_key);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (key_exch) {
            retmin = ntlm_encrypted_session_key(&key_exchange_key,
                                                &ctx->exported_session_key,
                                                &encrypted_random_session_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        }

        if (in_flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)) {
            retmin = ntlm_signseal_keys(in_flags,
                                        (ctx->role == GSSNTLM_CLIENT),
                                        &ctx->exported_session_key,
                                        &ctx->send.sign_key,
                                        &ctx->recv.sign_key,
                                        &ctx->send.seal_key,
                                        &ctx->recv.seal_key,
                                        &ctx->send.seal_handle,
                                        &ctx->recv.seal_handle);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        }

        /* TODO: Compute MIC if necessary */

        /* in_flags all verified, assign as current flags */
        ctx->neg_flags |= in_flags;
        enc_sess_key.data = encrypted_random_session_key.data;
        enc_sess_key.length = encrypted_random_session_key.length;

        retmin = ntlm_encode_auth_msg(ctx->ntlm, ctx->neg_flags,
                                      &lm_chal_resp,  &nt_chal_resp,
                                      ctx->cred.cred.user.user.data.user.domain,
                                      ctx->cred.cred.user.user.data.user.name,
                                      ctx->workstation, &enc_sess_key, NULL,
                                      &ctx->auth_msg);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->stage = NTLMSSP_STAGE_AUTHENTICATE;

        output_token->value = malloc(ctx->auth_msg.length);
        if (!output_token->value) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(output_token->value, ctx->auth_msg.data, ctx->auth_msg.length);
        output_token->length = ctx->auth_msg.length;

        retmaj = GSS_S_COMPLETE;
    }

done:
    if ((retmaj != GSS_S_COMPLETE) &&
        (retmaj != GSS_S_CONTINUE_NEEDED)) {
        gssntlm_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&ctx, NULL);
        *minor_status = retmin;
    }
    *context_handle = (gss_ctx_id_t)ctx;
    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        /* we copy creds around, so always free if not passed in */
        gssntlm_release_cred(&tmpmin, (gss_cred_id_t *)&cred);
    }
    ntlm_free_buffer_data(&target_info);
    ntlm_free_buffer_data(&nt_chal_resp);
    ntlm_free_buffer_data(&lm_chal_resp);
    return retmaj;
}

uint32_t gssntlm_delete_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_buffer_t output_token)
{
    struct gssntlm_ctx *ctx;
    int ret;

    *minor_status = 0;

    if (!context_handle) return GSS_S_CALL_INACCESSIBLE_READ;
    if (*context_handle == NULL) return GSS_S_COMPLETE;

    ctx = (struct gssntlm_ctx *)*context_handle;

    gssntlm_int_release_cred(&ctx->cred);
    ctx->cred.type = GSSNTLM_CRED_NONE;

    ret = ntlm_free_ctx(&ctx->ntlm);

    safefree(ctx->nego_msg.data);
    safefree(ctx->chal_msg.data);
    safefree(ctx->auth_msg.data);
    ctx->nego_msg.length = 0;
    ctx->chal_msg.length = 0;
    ctx->auth_msg.length = 0;

    safefree(*context_handle);

    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}
