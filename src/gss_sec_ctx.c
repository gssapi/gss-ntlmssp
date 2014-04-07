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
    char *trgt_name = NULL;
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
    int lm_compat_lvl;
    uint32_t tmpmin;
    uint32_t retmin = 0;
    uint32_t retmaj = 0;
    uint8_t sec_req;
    bool key_exch;

    ctx = (struct gssntlm_ctx *)(*context_handle);

    /* reset return values */
    *minor_status = 0;
    if (actual_mech_type) *actual_mech_type = NULL;
    if (ret_flags) *ret_flags = 0;
    if (time_rec) *time_rec = 0;

    if (output_token == GSS_C_NO_BUFFER) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

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

    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        if (req_flags & GSS_C_ANON_FLAG) {
            retmaj = GSS_S_UNAVAILABLE;
            goto done;
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
        if (cred->type != GSSNTLM_CRED_USER) {
            retmin = EINVAL;
            retmaj = GSS_S_CRED_UNAVAIL;
            goto done;
        }
    }

    if (ctx == NULL) {

        /* first call */
        ctx = calloc(1, sizeof(struct gssntlm_ctx));
        if (!ctx) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        retmin = gssntlm_copy_name(&cred->cred.user.user,
                                   &ctx->source_name);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (server) {
            retmin = gssntlm_copy_name(server, &ctx->target_name);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
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
        if (req_flags & GSS_C_DATAGRAM_FLAG) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_DATAGRAM |
                              NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        if (cred->type == GSSNTLM_CRED_USER &&
            cred->cred.user.user.data.user.domain) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
            domain = cred->cred.user.user.data.user.domain;
        }
        if (ctx->workstation) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
            workstation = ctx->workstation;
        }

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        sec_req = gssntlm_required_security(lm_compat_lvl, ctx->role);
        if (sec_req == 0xff) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        if (!(sec_req & SEC_LM_OK)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }
        if (!(sec_req & SEC_EXT_SEC_OK)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        retmin = ntlm_init_ctx(&ctx->ntlm);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        /* only in connecionless mode we may receive an input buffer
         * on the the first call, if DATAGRAM is not selected and
         * we have a buffer here, somethings wrong */
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM) {

            if ((input_token == GSS_C_NO_BUFFER) ||
                (input_token->length == 0)) {
                /* in connectionless mode we return an empty buffer here:
                 * see MS-NLMP 1.3.1.3 and 1.7 */
                output_token->value = NULL;
                output_token->length = 0;

                /* and return the ball */
                ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
                retmaj = GSS_S_CONTINUE_NEEDED;
                goto done;
            }
        } else {

            if (input_token && input_token->length != 0) {
                retmin = EINVAL;
                retmaj = GSS_S_DEFECTIVE_TOKEN;
                goto done;
            }

            retmin = ntlm_encode_neg_msg(ctx->ntlm, ctx->neg_flags,
                                         domain, workstation, &ctx->nego_msg);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            output_token->value = malloc(ctx->nego_msg.length);
            if (!output_token->value) {
                retmin = ENOMEM;
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            memcpy(output_token->value, ctx->nego_msg.data, ctx->nego_msg.length);
            output_token->length = ctx->nego_msg.length;

            ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
            retmaj = GSS_S_CONTINUE_NEEDED;
            goto done;
        }

        /* If we get here we are in connectionless mode and where called
         * with a chalenge message in the input buffer */
        ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
    }

    if (ctx == NULL) {
        /* this should not happen */
        retmin = EFAULT;
        retmaj = GSS_S_FAILURE;
        goto done;

    } else {

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

        if (msg_type != CHALLENGE_MESSAGE ||
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

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        sec_req = gssntlm_required_security(lm_compat_lvl, ctx->role);
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
        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_128) &&
            (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_56)) &&
            (!(in_flags & NTLMSSP_NEGOTIATE_128))) {
            retmaj = GSS_S_UNAVAILABLE;
            goto done;
        }
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

        if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
            if (!(in_flags & NTLMSSP_NEGOTIATE_DATAGRAM)) {
                /* no common understanding */
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            if (!(in_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                /* no common understanding */
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        } else {
            in_flags &= ~NTLMSSP_NEGOTIATE_DATAGRAM;
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
            } else {
                long int tdiff;
                tdiff = ntlm_timestamp_now() - srv_time;
                if ((tdiff / 10000000) > MAX_CHALRESP_LIFETIME) {
                    retmin = EINVAL;
                    retmaj = GSS_S_CONTEXT_EXPIRED;
                    goto done;
                }
            }

            /* Random client challenge */
            retmin = RAND_BUFFER(&cli_chal);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Key */
            retmin = NTOWFv2(ctx->ntlm, &cred->cred.user.nt_hash,
                             cred->cred.user.user.data.user.name,
                             cred->cred.user.user.data.user.domain,
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

            if (target_info.length == 0) {
                /* LMv2 Response
                 * (only sent if challenge response has not target_info*/
                retmin = ntlmv2_compute_lm_response(&ntlmv2_key,
                                                    server_chal, client_chal,
                                                    &lm_chal_resp);
                if (retmin) {
                    retmaj = GSS_S_FAILURE;
                    goto done;
                }
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

            retmin = ntlm_compute_nt_response(&cred->cred.user.nt_hash,
                                              ext_sec, server_chal,
                                              client_chal, &nt_response);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            if (!ext_sec && NoLMResponseNTLMv1) {
                memcpy(lm_response.data, nt_response.data, 24);
            } else {
                retmin = ntlm_compute_lm_response(&cred->cred.user.lm_hash,
                                                  ext_sec, server_chal,
                                                  client_chal, &lm_response);
                if (retmin) {
                    retmaj = GSS_S_FAILURE;
                    goto done;
                }
            }

            retmin = ntlm_session_base_key(&cred->cred.user.nt_hash,
                                           &session_base_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            retmin = KXKEY(ctx->ntlm, ext_sec,
                           (in_flags & NTLMSSP_NEGOTIATE_LM_KEY),
                           (in_flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY),
                           server_chal, &cred->cred.user.lm_hash,
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
            retmin = ntlm_signseal_keys(in_flags, true,
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

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
            ctx->gss_flags |= GSS_C_INTEG_FLAG;
        }
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
            ctx->gss_flags |= GSS_C_CONF_FLAG & GSS_C_INTEG_FLAG;
        }

        enc_sess_key.data = encrypted_random_session_key.data;
        enc_sess_key.length = encrypted_random_session_key.length;

        retmin = ntlm_encode_auth_msg(ctx->ntlm, ctx->neg_flags,
                                      &lm_chal_resp,  &nt_chal_resp,
                                      cred->cred.user.user.data.user.domain,
                                      cred->cred.user.user.data.user.name,
                                      ctx->workstation, &enc_sess_key, NULL,
                                      &ctx->auth_msg);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->stage = NTLMSSP_STAGE_DONE;

        output_token->value = malloc(ctx->auth_msg.length);
        if (!output_token->value) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(output_token->value, ctx->auth_msg.data, ctx->auth_msg.length);
        output_token->length = ctx->auth_msg.length;

        /* For now use the same as the challenge/response lifetime (36h) */
        ctx->expiration_time = time(NULL) + MAX_CHALRESP_LIFETIME;
        ctx->established = true;

        retmaj = GSS_S_COMPLETE;
    }

done:
    if ((retmaj != GSS_S_COMPLETE) &&
        (retmaj != GSS_S_CONTINUE_NEEDED)) {
        gssntlm_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&ctx, NULL);
        *minor_status = retmin;
    } else {
        if (ret_flags) *ret_flags = ctx->gss_flags;
        if (time_rec) *time_rec = GSS_C_INDEFINITE;
    }
    *context_handle = (gss_ctx_id_t)ctx;
    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        /* do not leak it, if not passed in */
        gssntlm_release_cred(&tmpmin, (gss_cred_id_t *)&cred);
    }
    safefree(trgt_name);
    safefree(trginfo_name);
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
    if (*context_handle == NULL) return GSS_S_NO_CONTEXT;

    ctx = (struct gssntlm_ctx *)*context_handle;

    safefree(ctx->workstation);

    ret = ntlm_free_ctx(&ctx->ntlm);

    safefree(ctx->nego_msg.data);
    safefree(ctx->chal_msg.data);
    safefree(ctx->auth_msg.data);
    ctx->nego_msg.length = 0;
    ctx->chal_msg.length = 0;
    ctx->auth_msg.length = 0;

    gssntlm_int_release_name(&ctx->source_name);
    gssntlm_int_release_name(&ctx->target_name);

    RC4_FREE(&ctx->send.seal_handle);
    RC4_FREE(&ctx->recv.seal_handle);

    safezero((uint8_t *)ctx, sizeof(struct gssntlm_ctx));
    safefree(*context_handle);

    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

uint32_t gssntlm_context_time(uint32_t *minor_status,
                              gss_ctx_id_t context_handle,
                              uint32_t *time_rec)
{
    struct gssntlm_ctx *ctx;
    time_t now;
    uint32_t retmaj;

    *minor_status = 0;

    if (context_handle == GSS_C_NO_CONTEXT) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, &now);
    if (retmaj) return retmaj;

    *time_rec = ctx->expiration_time - now;
    return GSS_S_COMPLETE;
}

uint32_t gssntlm_accept_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_cred_id_t acceptor_cred_handle,
                                    gss_buffer_t input_token,
                                    gss_channel_bindings_t input_chan_bindings,
                                    gss_name_t *src_name,
                                    gss_OID *mech_type,
                                    gss_buffer_t output_token,
                                    uint32_t *ret_flags,
                                    uint32_t *time_rec,
                                    gss_cred_id_t *delegated_cred_handle)
{
    struct gssntlm_ctx *ctx;
    struct gssntlm_cred *cred;
    int lm_compat_lvl = -1;
    char *workstation = NULL;
    char *domain = NULL;
    struct ntlm_buffer challenge = { 0 };
    struct gssntlm_name *server_name = NULL;
    char *computer_name = NULL;
    gss_buffer_desc tmpbuf;
    uint64_t timestamp;
    struct ntlm_buffer target_info = { 0 };
    struct ntlm_buffer nt_chal_resp = { 0 };
    struct ntlm_buffer lm_chal_resp = { 0 };
    struct ntlm_buffer enc_sess_key = { 0 };
    struct ntlm_key encrypted_random_session_key = { .length = 16 };
    struct ntlm_key key_exchange_key = { .length = 16 };
    uint8_t mic_data[16];
    struct ntlm_buffer mic = { mic_data, 16 };
    char *dom_name = NULL;
    char *usr_name = NULL;
    char *wks_name = NULL;
    struct gssntlm_name *gss_usrname = NULL;
    struct gssntlm_cred *usr_cred = NULL;
    uint32_t retmin = 0;
    uint32_t retmaj = 0;
    uint32_t tmpmin;
    uint32_t in_flags;
    uint32_t msg_type;
    uint8_t sec_req;
    char *p;

    if (context_handle == NULL) return GSS_S_CALL_INACCESSIBLE_READ;
    if (output_token == GSS_C_NO_BUFFER) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    /* reset return values */
    *minor_status = 0;
    if (src_name) *src_name = GSS_C_NO_NAME;
    if (mech_type) *mech_type = GSS_C_NO_OID;
    if (ret_flags) *ret_flags = 0;
    if (time_rec) *time_rec = 0;
    if (delegated_cred_handle) *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (acceptor_cred_handle) {
        cred = (struct gssntlm_cred *)acceptor_cred_handle;
        if (cred->type != GSSNTLM_CRED_SERVER) {
            retmaj = GSS_S_DEFECTIVE_CREDENTIAL;
            goto done;
        }
        if (cred->cred.server.name.type != GSSNTLM_NAME_SERVER) {
            retmaj = GSS_S_DEFECTIVE_CREDENTIAL;
            goto done;
        }
        retmaj = gssntlm_duplicate_name(&retmin,
                                (const gss_name_t)&cred->cred.server.name,
                                (gss_name_t *)&server_name);
        if (retmaj) goto done;
    }

    if (*context_handle == GSS_C_NO_CONTEXT) {

        /* first call */
        ctx = calloc(1, sizeof(struct gssntlm_ctx));
        if (!ctx) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        /* FIXME: add call to determine if we are any other type of
         * server, including setting up callbacks to perform validation
         * against a remote DC */
        ctx->role = GSSNTLM_SERVER;

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        sec_req = gssntlm_required_security(lm_compat_lvl, ctx->role);
        if (sec_req == 0xff) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->neg_flags = NTLMSSP_DEFAULT_ALLOWED_SERVER_FLAGS;
        /* Fixme: How do we allow anonymous negotition ? */

        if ((sec_req & SEC_LM_OK) || (sec_req & SEC_DC_LM_OK)) {
            ctx->neg_flags |= NTLMSSP_REQUEST_NON_NT_SESSION_KEY;
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
        }
        if (sec_req & SEC_EXT_SEC_OK) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        retmin = ntlm_init_ctx(&ctx->ntlm);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (input_token && input_token->length != 0) {
            ctx->nego_msg.data = malloc(input_token->length);
            if (!ctx->nego_msg.data) {
                retmin = ENOMEM;
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            memcpy(ctx->nego_msg.data, input_token->value, input_token->length);
            ctx->nego_msg.length = input_token->length;

            retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->nego_msg, &msg_type);
            if (retmin || (msg_type != NEGOTIATE_MESSAGE)) {
                retmaj = GSS_S_DEFECTIVE_TOKEN;
                goto done;
            }

            retmin = ntlm_decode_neg_msg(ctx->ntlm, &ctx->nego_msg, &in_flags,
                                         &domain, &workstation);
            if (retmin) {
                retmaj = GSS_S_DEFECTIVE_TOKEN;
                goto done;
            }

            /* leave only the crossing between requested and allowed flags */
            ctx->neg_flags &= in_flags;
        } else {
            /* If there is no negotiate message set datagram mode */
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_DATAGRAM | \
                              NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        /* TODO: Support MS-NLMP ServerBlock ? */

        /* TODO: Check some minimum required flags ? */
        /* TODO: Check MS-NLMP ServerRequire128bitEncryption */

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
            /* Choose unicode in preferemce if both are set */
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
        } else if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_OEM)) {
            /* no agreement */
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            ctx->neg_flags &= ~NTLMSSP_REQUEST_NON_NT_SESSION_KEY;
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
        }

        /* TODO: support Domain type */
        if (true) {
            ctx->neg_flags |= NTLMSSP_TARGET_TYPE_SERVER;
            ctx->neg_flags &= ~NTLMSSP_TARGET_TYPE_DOMAIN;
        }

        if (ctx->neg_flags & NTLMSSP_REQUEST_TARGET) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
            ctx->gss_flags |= GSS_C_INTEG_FLAG;
        }
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
            ctx->gss_flags |= GSS_C_CONF_FLAG;
        }
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM) {
            ctx->gss_flags |= GSS_C_DATAGRAM_FLAG;
        }

        /* Random server challenge */
        challenge.data = ctx->server_chal;
        challenge.length = 8;
        retmin = RAND_BUFFER(&challenge);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        /* acquire our own name */
        if (!server_name) {
            tmpbuf.value = "";
            tmpbuf.length = 0;
            retmaj = gssntlm_import_name_by_mech(&retmin,
                                                 &gssntlm_oid,
                                                 &tmpbuf,
                                                 GSS_C_NT_HOSTBASED_SERVICE,
                                                 (gss_name_t *)&server_name);
            if (retmaj) goto done;
        }

        retmin = gssntlm_copy_name(server_name, &ctx->target_name);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        computer_name = strdup(server_name->data.server.name);
        if (!computer_name) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        if ((p = strchr(server_name->data.server.name, '.')) != NULL) {
            /* we want only the non qualified computer name for now */
            *p = '\0';
        }

        timestamp = ntlm_timestamp_now();

        retmin = ntlm_encode_target_info(ctx->ntlm, computer_name, NULL,
                                         NULL, NULL, NULL,
                                         NULL, &timestamp,
                                         NULL, computer_name, NULL,
                                         &target_info);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        retmin = ntlm_encode_chal_msg(ctx->ntlm, ctx->neg_flags,
                                      computer_name, &challenge,
                                      &target_info, &ctx->chal_msg);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        ctx->stage = NTLMSSP_STAGE_CHALLENGE;

        output_token->value = malloc(ctx->chal_msg.length);
        if (!output_token->value) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(output_token->value, ctx->chal_msg.data, ctx->chal_msg.length);
        output_token->length = ctx->chal_msg.length;

        retmaj = GSS_S_CONTINUE_NEEDED;

    } else {
        ctx = (struct gssntlm_ctx *)(*context_handle);

        if (ctx->role != GSSNTLM_SERVER) {
            retmaj = GSS_S_NO_CONTEXT;
            goto done;
        }

        if ((input_token == GSS_C_NO_BUFFER) ||
            (input_token->length == 0)) {
            retmin = EINVAL;
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        ctx->auth_msg.data = malloc(input_token->length);
        if (!ctx->auth_msg.data) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(ctx->auth_msg.data, input_token->value, input_token->length);
        ctx->auth_msg.length = input_token->length;

        retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->auth_msg, &msg_type);
        if (retmin) {
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        if (msg_type != AUTHENTICATE_MESSAGE ||
                ctx->stage != NTLMSSP_STAGE_CHALLENGE) {
            retmaj = GSS_S_NO_CONTEXT;
            goto done;
        }

        retmin = ntlm_decode_auth_msg(ctx->ntlm, &ctx->auth_msg,
                                      ctx->neg_flags,
                                      &lm_chal_resp, &nt_chal_resp,
                                      &dom_name, &usr_name, &wks_name,
                                      &enc_sess_key, &mic);
        if (retmin) {
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM) &&
            !(ctx->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
            retmin = EINVAL;
            retmaj = GSS_S_DEFECTIVE_TOKEN;
            goto done;
        }

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        sec_req = gssntlm_required_security(lm_compat_lvl, ctx->role);
        if (sec_req == 0xff) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (((usr_name == NULL) || (usr_name[0] == '\0')) &&
            (nt_chal_resp.length == 0) &&
            (((lm_chal_resp.length == 1) && (lm_chal_resp.data[0] == '\0')) ||
             (lm_chal_resp.length == 0))) {
            /* Anonymous auth */
            /* FIXME: not supported for now */
            retmin = EINVAL;
            retmaj = GSS_S_FAILURE;

        } else if (sec_req & SEC_V2_ONLY) {

            /* ### NTLMv2 ### */
            struct ntlm_key ntlmv2_key = { .length = 16 };
            struct ntlm_buffer nt_proof = { 0 };
            char useratdom[1024];
            size_t ulen, dlen, uadlen;
            gss_buffer_desc usrname;

            if (!dom_name) {
                dom_name = strdup("");
                if (!dom_name) {
                    retmin = ENOMEM;
                    retmaj = GSS_S_FAILURE;
                    goto done;
                }
            }

            ulen = strlen(usr_name);
            dlen = strlen(dom_name);
            if (ulen + dlen + 2 > 1024) {
                retmin = EINVAL;
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            strncpy(useratdom, usr_name, ulen);
            uadlen = ulen;
            if (dlen) {
                useratdom[uadlen] = '@';
                uadlen++;
                strncpy(&useratdom[uadlen], dom_name, dlen);
                uadlen += dlen;
            }
            useratdom[uadlen] = '\0';

            usrname.value = useratdom;
            usrname.length = uadlen;
            retmaj = gssntlm_import_name(&retmin, &usrname,
                                         GSS_C_NT_USER_NAME,
                                         (gss_name_t *)&gss_usrname);
            if (retmaj) goto done;

            retmaj = gssntlm_acquire_cred(&retmin,
                                          (gss_name_t)gss_usrname,
                                          GSS_C_INDEFINITE,
                                          GSS_C_NO_OID_SET,
                                          GSS_C_INITIATE,
                                          (gss_cred_id_t *)&usr_cred,
                                          NULL, NULL);
            if (retmaj) goto done;

            retmin = gssntlm_copy_name(gss_usrname, &ctx->source_name);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Key */
            retmin = NTOWFv2(ctx->ntlm, &usr_cred->cred.user.nt_hash,
                             usr_cred->cred.user.user.data.user.name,
                             usr_cred->cred.user.user.data.user.domain,
                             &ntlmv2_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* NTLMv2 Response */
            retmin = ntlmv2_verify_nt_response(&nt_chal_resp, &ntlmv2_key,
                                               ctx->server_chal);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            /* FIXME: retries using NULL as domain name in case of failure */

            /* LMv2 Response */
            retmin = ntlmv2_verify_lm_response(&lm_chal_resp, &ntlmv2_key,
                                               ctx->server_chal);
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

            /* FIXME: Verify MIC if client sent it */

        } else {
            /* ### NTLMv1 ### */
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
            memcpy(encrypted_random_session_key.data, enc_sess_key.data, 16);
            ctx->exported_session_key.length = 16;

            retmin = ntlm_encrypted_session_key(&key_exchange_key,
                                                &encrypted_random_session_key,
                                                &ctx->exported_session_key);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
        } else {
            ctx->exported_session_key = key_exchange_key;
        }

        if (ctx->neg_flags & (NTLMSSP_NEGOTIATE_SIGN |
                                NTLMSSP_NEGOTIATE_SEAL)) {
            retmin = ntlm_signseal_keys(ctx->neg_flags, false,
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

        if (src_name) {
            retmaj = gssntlm_duplicate_name(&retmin,
                                            (gss_name_t)&ctx->source_name,
                                            src_name);
            if (retmaj) {
                goto done;
            }
        }

        ctx->stage = NTLMSSP_STAGE_DONE;
        ctx->expiration_time = time(NULL) + MAX_CHALRESP_LIFETIME;
        ctx->established = true;
        retmaj = GSS_S_COMPLETE;
    }

done:

    if ((retmaj != GSS_S_COMPLETE) &&
        (retmaj != GSS_S_CONTINUE_NEEDED)) {
        gssntlm_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&ctx, NULL);
        *minor_status = retmin;
    } else {
        if (ret_flags) *ret_flags = ctx->gss_flags;
        if (time_rec) *time_rec = GSS_C_INDEFINITE;
    }
    *context_handle = (gss_ctx_id_t)ctx;
    gssntlm_release_name(&tmpmin, (gss_name_t *)&server_name);
    safefree(computer_name);
    safefree(workstation);
    safefree(domain);
    safefree(usr_name);
    safefree(dom_name);
    safefree(wks_name);
    ntlm_free_buffer_data(&target_info);
    return retmaj;
}

uint32_t gssntlm_inquire_context(uint32_t *minor_status,
                                 gss_ctx_id_t context_handle,
                                 gss_name_t *src_name,
                                 gss_name_t *targ_name,
                                 uint32_t *lifetime_rec,
                                 gss_OID *mech_type,
                                 uint32_t *ctx_flags,
                                 int *locally_initiated,
                                 int *open)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmaj;
    uint32_t retmin;
    time_t now;

    *minor_status = 0;

    ctx = (struct gssntlm_ctx *)context_handle;
    if (!ctx) return GSS_S_NO_CONTEXT;

    if (src_name) {
        retmaj = gssntlm_duplicate_name(&retmin,
                                        (gss_name_t)&ctx->source_name,
                                        src_name);
        if (retmaj) return retmaj;
    }

    if (targ_name) {
        retmaj = gssntlm_duplicate_name(&retmin,
                                        (gss_name_t)&ctx->target_name,
                                        targ_name);
        if (retmaj) return retmaj;
    }

    if (mech_type) {
        *mech_type = discard_const(&gssntlm_oid);
    }

    if (ctx_flags) {
        *ctx_flags = ctx->gss_flags;
    }

    if (locally_initiated) {
        if (ctx->role == GSSNTLM_CLIENT) {
            *locally_initiated = 1;
        } else {
            *locally_initiated = 0;
        }
    }

    if (ctx->established) {
        if (lifetime_rec) {
            now = time(NULL);
            if (ctx->expiration_time > now) {
                *lifetime_rec = 0;
            } else {
                *lifetime_rec = ctx->expiration_time - now;
            }
        }
        if (open) {
            *open = 1;
        }
    } else {
        if (lifetime_rec) {
            *lifetime_rec = 0;
        }
        if (open) {
            *open = 0;
        }
    }

    return GSS_S_COMPLETE;
}

gss_OID_desc set_seq_num_oid = {
    GSS_NTLMSSP_SET_SEQ_NUM_OID_LENGTH,
    GSS_NTLMSSP_SET_SEQ_NUM_OID_STRING
};

uint32_t gssntlm_set_sec_context_option(uint32_t *minor_status,
                                        gss_ctx_id_t *context_handle,
                                        const gss_OID desired_object,
                                        const gss_buffer_t value)
{
    struct gssntlm_ctx *ctx;

    if (minor_status == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (context_handle == NULL || *context_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (desired_object == GSS_C_NO_OID) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    ctx = (struct gssntlm_ctx *)*context_handle;

    *minor_status = 0;

    /* set seq num */
    if (gss_oid_equal(desired_object, &set_seq_num_oid)) {
        if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {

            if (value->length != 4) {
                *minor_status = EINVAL;
                return GSS_S_FAILURE;
            }

            memcpy(&ctx->recv.seq_num, value->value, value->length);
            ctx->send.seq_num = ctx->recv.seq_num;
            return GSS_S_COMPLETE;
        } else {
            *minor_status = EACCES;
            return GSS_S_UNAUTHORIZED;
        }
    }

    *minor_status = EINVAL;
    return GSS_S_UNAVAILABLE;
}
