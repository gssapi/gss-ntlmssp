/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include <errno.h>
#include <string.h>
#include "gss_ntlmssp.h"


uint32_t gssntlm_cli_auth(uint32_t *minor,
                          struct gssntlm_ctx *ctx,
                          struct gssntlm_cred *cred,
                          struct ntlm_buffer *target_info,
                          uint32_t in_flags,
                          gss_channel_bindings_t input_chan_bindings)
{
    struct ntlm_buffer nt_chal_resp = { 0 };
    struct ntlm_buffer lm_chal_resp = { 0 };
    struct ntlm_buffer client_target_info = { 0 };
    struct ntlm_key key_exchange_key = { .length = 16 };
    struct ntlm_key encrypted_random_session_key = { .length = 16 };
    struct ntlm_buffer enc_sess_key = { 0 };
    struct ntlm_buffer auth_mic = { NULL, 16 };
    uint8_t micbuf[16];
    struct ntlm_buffer mic = { micbuf, 16 };
    bool add_mic = false;
    bool key_exch;
    uint32_t retmaj = GSS_S_FAILURE;
    uint32_t retmin = 0;

    switch (cred->type) {

    case GSSNTLM_CRED_USER:

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

        } else if (ctx->sec_req & SEC_V2_ONLY) {

            /* ### NTLMv2 ### */
            uint8_t client_chal[8];
            struct ntlm_buffer cli_chal = { client_chal, 8 };
            struct ntlm_key ntlmv2_key = { .length = 16 };
            struct ntlm_buffer nt_proof = { 0 };
            struct ntlm_buffer cb = { 0 };
            uint64_t srv_time = 0;

            if (target_info->length == 0 &&
                input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
                retmaj = GSS_S_UNAVAILABLE;
                goto done;
            }

            if (target_info->length > 0) {
                bool *add_mic_ptr = NULL;
                bool protect;

                if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
                    if (input_chan_bindings->initiator_addrtype != 0 ||
                        input_chan_bindings->initiator_address.length != 0 ||
                        input_chan_bindings->acceptor_addrtype != 0 ||
                        input_chan_bindings->acceptor_address.length != 0 ||
                        input_chan_bindings->application_data.length == 0) {
                        retmin = EINVAL;
                        retmaj = GSS_S_BAD_BINDINGS;
                        goto done;
                    }
                    cb.length = input_chan_bindings->application_data.length;
                    cb.data = input_chan_bindings->application_data.value;
                }

                protect = in_flags & (NTLMSSP_NEGOTIATE_SIGN
                                      | NTLMSSP_NEGOTIATE_SEAL);
                if (protect) {
                    if (ctx->int_flags & NTLMSSP_CTX_FLAG_SPNEGO_CAN_MIC) {
                        add_mic_ptr = &add_mic;
                    }
                }

                retmin = ntlm_process_target_info(
                                            ctx->ntlm, protect, target_info,
                                            ctx->target_name.data.server.name,
                                            &cb, &client_target_info,
                                            &srv_time, add_mic_ptr);
                if (retmin) {
                    if (retmin == ERR_DECODE) {
                        retmaj = GSS_S_DEFECTIVE_TOKEN;
                    } else {
                        retmaj = GSS_S_FAILURE;
                    }
                    goto done;
                }

                if (srv_time != 0) {
                    long int tdiff;
                    tdiff = ntlm_timestamp_now() - srv_time;
                    if ((tdiff / 10000000) > MAX_CHALRESP_LIFETIME) {
                        retmin = EINVAL;
                        retmaj = GSS_S_CONTEXT_EXPIRED;
                        goto done;
                    }
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
                                                ctx->server_chal, client_chal,
                                                srv_time, &client_target_info,
                                                &nt_chal_resp);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            if (target_info->length == 0) {
                /* LMv2 Response
                 * (only sent if challenge response has no target_info) */
                retmin = ntlmv2_compute_lm_response(&ntlmv2_key,
                                                    ctx->server_chal,
                                                    client_chal,
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
                                              ext_sec, ctx->server_chal,
                                              client_chal, &nt_response);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }

            if (!ext_sec && NoLMResponseNTLMv1) {
                memcpy(lm_response.data, nt_response.data, 24);
            } else {
                retmin = ntlm_compute_lm_response(&cred->cred.user.lm_hash,
                                                  ext_sec, ctx->server_chal,
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
                           ctx->server_chal, &cred->cred.user.lm_hash,
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

        /* in_flags all verified, assign as current flags */
        ctx->neg_flags |= in_flags;

        enc_sess_key.data = encrypted_random_session_key.data;
        enc_sess_key.length = encrypted_random_session_key.length;

        retmin = ntlm_encode_auth_msg(ctx->ntlm, ctx->neg_flags,
                                      &lm_chal_resp,  &nt_chal_resp,
                                      cred->cred.user.user.data.user.domain,
                                      cred->cred.user.user.data.user.name,
                                      ctx->workstation, &enc_sess_key,
                                      add_mic ? &auth_mic : NULL,
                                      &ctx->auth_msg);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }

        /* Now we need to calculate the MIC, because the MIC is part of the
         * message it protects, ntlm_encode_auth_msg() always add a zeroeth
         * buffer, however it returns in data_mic the pointer to the actual
         * area in the auth_msg that points at the mic, so we can backfill */
        if (add_mic) {
            retmin = ntlm_mic(&ctx->exported_session_key, &ctx->nego_msg,
                              &ctx->chal_msg, &ctx->auth_msg, &mic);
            if (retmin) {
                retmaj = GSS_S_FAILURE;
                goto done;
            }
            /* now that we have the mic, copy it into the auth message */
            memcpy(auth_mic.data, mic.data, 16);

            /* Make sure SPNEGO gets to know it has to add mechlistMIC too */
            ctx->int_flags |= NTLMSSP_CTX_FLAG_AUTH_WITH_MIC;
        }

        retmin = 0;
        retmaj = GSS_S_COMPLETE;
        break;

    default:
        retmin = EINVAL;
        retmaj = GSS_S_FAILURE;
    }

done:
    ntlm_free_buffer_data(&client_target_info);
    ntlm_free_buffer_data(&nt_chal_resp);
    ntlm_free_buffer_data(&lm_chal_resp);
    *minor = retmin;
    return retmaj;
}


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
