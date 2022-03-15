/* Copyright 2013 Simo Sorce <simo@samba.org>, see COPYING for license */

#include <endian.h>
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
    char *nb_computer_name = NULL;
    char *nb_domain_name = NULL;
    struct gssntlm_name *client_name = NULL;
    uint32_t in_flags;
    uint32_t msg_type;
    char *trgt_name = NULL;
    struct ntlm_buffer challenge = { 0 };
    struct ntlm_buffer target_info = { 0 };
    int lm_compat_lvl;
    uint32_t tmpmin;
    uint32_t retmin = 0;
    uint32_t retmaj = 0;

    ctx = (struct gssntlm_ctx *)(*context_handle);

    /* reset return values */
    if (actual_mech_type) *actual_mech_type = NULL;
    if (ret_flags) *ret_flags = 0;
    if (time_rec) *time_rec = 0;

    if (output_token == GSS_C_NO_BUFFER) {
        return GSSERRS(0, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    if (target_name) {
        server = (struct gssntlm_name *)target_name;
        if (server->type != GSSNTLM_NAME_SERVER) {
            return GSSERRS(ERR_NOSRVNAME, GSS_S_BAD_NAMETYPE);
        }
        if (!server->data.server.name ||
            !server->data.server.name[0]) {
            return GSSERRS(ERR_NONAME, GSS_S_BAD_NAME);
        }
    }

    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        if (req_flags & GSS_C_ANON_FLAG) {
            set_GSSERRS(ERR_NOARG, GSS_S_UNAVAILABLE);
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
        if (cred->type != GSSNTLM_CRED_USER &&
            cred->type != GSSNTLM_CRED_EXTERNAL) {
            set_GSSERRS(ERR_NOARG, GSS_S_CRED_UNAVAIL);
            goto done;
        }
        if (cred->type == GSSNTLM_CRED_EXTERNAL &&
            cred->cred.external.creds_in_cache == 0) {
            set_GSSERRS(ERR_NOARG, GSS_S_CRED_UNAVAIL);
            goto done;
        }
    }

    if (ctx == NULL) {

        /* first call */
        ctx = calloc(1, sizeof(struct gssntlm_ctx));
        if (!ctx) {
            set_GSSERR(ENOMEM);
            goto done;
        }

        ctx->external_context = external_get_context();

        retmin = gssntlm_copy_name(&cred->cred.user.user,
                                   &ctx->source_name);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        if (server) {
            retmin = gssntlm_copy_name(server, &ctx->target_name);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }
        }

        ctx->gss_flags = req_flags;

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
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_SIGN |
                              NTLMSSP_NEGOTIATE_KEY_EXCH;
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

        /* acquire our own name */
        if (!client_name) {
            gss_buffer_desc tmpbuf;
            tmpbuf.value = discard_const("");
            tmpbuf.length = 0;
            retmaj = gssntlm_import_name_by_mech(&retmin,
                                                 &gssntlm_oid,
                                                 &tmpbuf,
                                                 GSS_C_NT_HOSTBASED_SERVICE,
                                                 (gss_name_t *)&client_name);
            if (retmaj) goto done;
        }

        retmin = netbios_get_names(ctx->external_context,
                                   client_name->data.server.name,
                                   &nb_computer_name, &nb_domain_name);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        ctx->workstation = strdup(nb_computer_name);
        if (!ctx->workstation) {
            set_GSSERR(ENOMEM);
            goto done;
        }

        gssntlm_set_role(ctx, GSSNTLM_CLIENT, nb_domain_name);

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        if (!gssntlm_required_security(lm_compat_lvl, ctx)) {
            set_GSSERR(ERR_BADLMLVL);
            goto done;
        }
        if (!gssntlm_sec_lm_ok(ctx)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }
        if (!gssntlm_ext_sec_ok(ctx)) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        retmin = ntlm_init_ctx(&ctx->ntlm);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        /* only in connectionless mode we may receive an input buffer
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
                set_GSSERRS(0, GSS_S_CONTINUE_NEEDED);
                goto done;
            }
        } else {

            if (input_token && input_token->length != 0) {
                set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
                goto done;
            }

            retmin = ntlm_encode_neg_msg(ctx->ntlm, ctx->neg_flags,
                                         NULL, NULL, &ctx->nego_msg);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }

            output_token->value = malloc(ctx->nego_msg.length);
            if (!output_token->value) {
                set_GSSERR(ENOMEM);
                goto done;
            }
            memcpy(output_token->value, ctx->nego_msg.data, ctx->nego_msg.length);
            output_token->length = ctx->nego_msg.length;

            ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
            set_GSSERRS(0, GSS_S_CONTINUE_NEEDED);
            goto done;
        }

        /* If we get here we are in connectionless mode and where called
         * with a chalenge message in the input buffer */
        ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
    }

    if (ctx == NULL) {
        /* this should not happen */
        set_GSSERR(ERR_IMPOSSIBLE);
        goto done;

    } else {

        if (!gssntlm_role_is_client(ctx)) {
            set_GSSERRS(ERR_WRONGCTX, GSS_S_NO_CONTEXT);
            goto done;
        }

        ctx->chal_msg.data = malloc(input_token->length);
        if (!ctx->chal_msg.data) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        memcpy(ctx->chal_msg.data, input_token->value, input_token->length);
        ctx->chal_msg.length = input_token->length;

        retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->chal_msg, &msg_type);
        if (retmin) {
            set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        if (msg_type != CHALLENGE_MESSAGE ||
                ctx->stage != NTLMSSP_STAGE_NEGOTIATE) {
            set_GSSERRS(ERR_WRONGMSG, GSS_S_NO_CONTEXT);
            goto done;
        }

        /* store challenge in ctx */
        challenge.data = ctx->server_chal;
        challenge.length = 8;
        retmin = ntlm_decode_chal_msg(ctx->ntlm, &ctx->chal_msg, &in_flags,
                                      &trgt_name, &challenge, &target_info);
        if (retmin) {
            set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        /* mask unacceptable flags */
        if (!gssntlm_sec_lm_ok(ctx)) {
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
            set_GSSERR(ERR_REQNEGFLAG);
            goto done;
        }
        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) &&
            (!(in_flags & NTLMSSP_NEGOTIATE_SEAL))) {
            set_GSSERR(ERR_REQNEGFLAG);
            goto done;
        }
        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) &&
            (!(in_flags & NTLMSSP_NEGOTIATE_SIGN))) {
            set_GSSERR(ERR_REQNEGFLAG);
            goto done;
        }

        if (!(in_flags & (NTLMSSP_NEGOTIATE_OEM |
                          NTLMSSP_NEGOTIATE_UNICODE))) {
            /* no common understanding */
            set_GSSERR(ERR_FAILNEGFLAGS);
            goto done;
        }

        if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
            if (!(in_flags & NTLMSSP_NEGOTIATE_DATAGRAM)) {
                /* no common understanding */
                set_GSSERR(ERR_FAILNEGFLAGS);
                goto done;
            }
            if (!(in_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                /* no common understanding */
                set_GSSERR(ERR_FAILNEGFLAGS);
                goto done;
            }
            if ((in_flags & NTLMSSP_NEGOTIATE_OEM) &&
                (in_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
                /* prefer Unicode */
                in_flags &= ~NTLMSSP_NEGOTIATE_OEM;
            }
        } else {
            in_flags &= ~NTLMSSP_NEGOTIATE_DATAGRAM;

            if ((in_flags & NTLMSSP_NEGOTIATE_OEM) &&
                (in_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
                /* server sent both?? This is broken, proceed only if there
                 * are no strings set in the challenge packet and downgrade
                 * to OEM charset hoping the server will cope */
                if (in_flags & (NTLMSSP_NEGOTIATE_TARGET_INFO |
                                NTLMSSP_TARGET_TYPE_SERVER |
                                NTLMSSP_TARGET_TYPE_DOMAIN)) {
                    set_GSSERR(ERR_BADNEGFLAGS);
                    goto done;
                } else {
                    in_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
                }
            }
        }

        /* Now that everything has been checked clear non
         * negotiated flags */
        ctx->neg_flags &= in_flags;

       retmaj = gssntlm_cli_auth(&retmin, ctx, cred, &target_info,
                                  in_flags, input_chan_bindings);
        if (retmaj) goto done;

        if (in_flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)) {
            retmin = ntlm_signseal_keys(in_flags, true,
                                        &ctx->exported_session_key,
                                        &ctx->crypto_state);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
            ctx->gss_flags |= GSS_C_INTEG_FLAG;
        }
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
            ctx->gss_flags |= GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
        }

        ctx->stage = NTLMSSP_STAGE_DONE;

        output_token->value = malloc(ctx->auth_msg.length);
        if (!output_token->value) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        memcpy(output_token->value, ctx->auth_msg.data, ctx->auth_msg.length);
        output_token->length = ctx->auth_msg.length;

        /* For now use the same as the challenge/response lifetime (36h) */
        ctx->expiration_time = time(NULL) + MAX_CHALRESP_LIFETIME;
        ctx->int_flags |= NTLMSSP_CTX_FLAG_ESTABLISHED;

        set_GSSERRS(0, GSS_S_COMPLETE);
    }

done:
    if ((retmaj != GSS_S_COMPLETE) &&
        (retmaj != GSS_S_CONTINUE_NEEDED)) {
        gssntlm_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&ctx, NULL);
    } else {
        if (actual_mech_type) *actual_mech_type = discard_const(&gssntlm_oid);
        if (ret_flags) *ret_flags = ctx->gss_flags;
        if (time_rec) *time_rec = GSS_C_INDEFINITE;
    }
    *context_handle = (gss_ctx_id_t)ctx;
    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        /* do not leak it, if not passed in */
        gssntlm_release_cred(&tmpmin, (gss_cred_id_t *)&cred);
    }
    gssntlm_release_name(&tmpmin, (gss_name_t *)&client_name);
    safefree(nb_computer_name);
    safefree(nb_domain_name);
    safefree(trgt_name);
    ntlm_free_buffer_data(&target_info);

    return GSSERR();
}

uint32_t gssntlm_delete_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_buffer_t output_token)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmin;
    uint32_t retmaj;
    int ret;

    if (!context_handle) {
        set_GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
        goto done;
    }
    if (*context_handle == NULL) {
        set_GSSERRS(ERR_NOARG, GSS_S_NO_CONTEXT);
        goto done;
    }

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

    ntlm_release_rc4_state(&ctx->crypto_state);

    external_free_context(ctx->external_context);

    safezero((uint8_t *)ctx, sizeof(struct gssntlm_ctx));
    safefree(*context_handle);

    set_GSSERRS(ret, ret ? GSS_S_FAILURE : GSS_S_COMPLETE);
done:
    return GSSERR();
}

uint32_t gssntlm_context_time(uint32_t *minor_status,
                              gss_ctx_id_t context_handle,
                              uint32_t *time_rec)
{
    struct gssntlm_ctx *ctx;
    time_t now;
    uint32_t retmin;
    uint32_t retmaj;

    if (context_handle == GSS_C_NO_CONTEXT) {
        set_GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
        goto done;
    }

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, &now);
    if (retmaj) {
        set_GSSERRS(ERR_BADCTX, retmaj);
        goto done;
    }

    *time_rec = ctx->expiration_time - now;
    set_GSSERRS(0, GSS_S_COMPLETE);
done:
    return GSSERR();
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
    struct gssntlm_cred *cred = NULL;
    int lm_compat_lvl = -1;
    struct ntlm_buffer challenge = { 0 };
    struct gssntlm_name *server_name = NULL;
    char *nb_computer_name = NULL;
    char *nb_domain_name = NULL;
    char *chal_target_name;
    uint64_t timestamp;
    struct ntlm_buffer target_info = { 0 };
    struct ntlm_buffer nt_chal_resp = { 0 };
    struct ntlm_buffer lm_chal_resp = { 0 };
    struct ntlm_buffer enc_sess_key = { 0 };
    struct ntlm_key encrypted_random_session_key = { .length = 16 };
    struct ntlm_key key_exchange_key = { .length = 16 };
    uint8_t micbuf[16];
    struct ntlm_buffer mic = { micbuf, 16 };
    char *dom_name = NULL;
    char *usr_name = NULL;
    char *wks_name = NULL;
    struct gssntlm_name *gss_usrname = NULL;
    struct gssntlm_cred *usr_cred = NULL;
    uint32_t retmin;
    uint32_t retmaj;
    uint32_t tmpmin;
    uint32_t in_flags;
    uint32_t msg_type;
    uint32_t av_flags = 0;
    struct ntlm_buffer unhashed_cb = { 0 };
    struct ntlm_buffer av_cb = { 0 };

    if (context_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (output_token == GSS_C_NO_BUFFER) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    if (src_name) *src_name = GSS_C_NO_NAME;
    if (mech_type) *mech_type = GSS_C_NO_OID;
    if (ret_flags) *ret_flags = 0;
    if (time_rec) *time_rec = 0;
    if (delegated_cred_handle) *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (acceptor_cred_handle) {
        cred = (struct gssntlm_cred *)acceptor_cred_handle;
        if (cred->type != GSSNTLM_CRED_SERVER) {
            set_GSSERRS(ERR_NOSRVCRED, GSS_S_DEFECTIVE_CREDENTIAL);
            goto done;
        }
        if (cred->cred.server.name.type != GSSNTLM_NAME_SERVER) {
            set_GSSERRS(ERR_NOSRVNAME, GSS_S_DEFECTIVE_CREDENTIAL);
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
            set_GSSERR(ENOMEM);
            goto done;
        }

        ctx->external_context = external_get_context();

        /* acquire our own name */
        if (!server_name) {
            gss_buffer_desc tmpbuf;
            tmpbuf.value = discard_const("");
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
            set_GSSERR(retmin);
            goto done;
        }

        retmin = netbios_get_names(ctx->external_context,
                                   server_name->data.server.name,
                                   &nb_computer_name, &nb_domain_name);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        ctx->workstation = strdup(nb_computer_name);
        if (!ctx->workstation) {
            set_GSSERR(ENOMEM);
            goto done;
        }

        gssntlm_set_role(ctx, GSSNTLM_SERVER, nb_domain_name);

        lm_compat_lvl = gssntlm_get_lm_compatibility_level();
        if (!gssntlm_required_security(lm_compat_lvl, ctx)) {
            set_GSSERR(ERR_BADLMLVL);
            goto done;
        }

        ctx->neg_flags = NTLMSSP_DEFAULT_SERVER_FLAGS;
        /* Fixme: How do we allow anonymous negotition ? */

        if (gssntlm_sec_lm_ok(ctx)) {
            ctx->neg_flags |= NTLMSSP_REQUEST_NON_NT_SESSION_KEY;
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
        }
        if (gssntlm_ext_sec_ok(ctx)) {
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        retmin = ntlm_init_ctx(&ctx->ntlm);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        if (input_token && input_token->length != 0) {
            ctx->nego_msg.data = malloc(input_token->length);
            if (!ctx->nego_msg.data) {
                set_GSSERR(ENOMEM);
                goto done;
            }
            memcpy(ctx->nego_msg.data, input_token->value, input_token->length);
            ctx->nego_msg.length = input_token->length;

            retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->nego_msg, &msg_type);
            if (retmin || (msg_type != NEGOTIATE_MESSAGE)) {
                set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
                goto done;
            }

            retmin = ntlm_decode_neg_msg(ctx->ntlm, &ctx->nego_msg, &in_flags,
                                         NULL, NULL);
            if (retmin) {
                set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
                goto done;
            }

            /* leave only the crossing between requested and allowed flags */
            ctx->neg_flags &= in_flags;

            /* Try to force the use of NTLMSSP_NEGOTIATE_VERSION even if the
             * client did not advertize it in their negotiate message, but
             * should be capable of providing it.
             * This is what Windows Server 2022 also does, and addresses
             * issues with older clients that incorrectly deal with MIC
             * calculations in absence of this flag. */
            if ((ctx->neg_flags & (NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                                    NTLMSSP_NEGOTIATE_SEAL |
                                    NTLMSSP_NEGOTIATE_SIGN))) {
                ctx->neg_flags |= NTLMSSP_NEGOTIATE_VERSION;
            }
        } else {
            /* If there is no negotiate message set datagram mode */
            ctx->neg_flags |= NTLMSSP_NEGOTIATE_DATAGRAM | \
                              NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        /* TODO: Check some minimum required flags ? */
        /* TODO: Check MS-NLMP ServerRequire128bitEncryption */

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
            /* Choose unicode in preferemce if both are set */
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
        } else if (!(ctx->neg_flags & NTLMSSP_NEGOTIATE_OEM)) {
            /* no agreement */
            set_GSSERR(ERR_FAILNEGFLAGS);
            goto done;
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            ctx->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
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
            set_GSSERR(retmin);
            goto done;
        }

        /* TODO: allow client applications to set a context option to
         * provide an av_flags default value so that flags like
         * MSVAVFLAGS_UNVERIFIED_SPN can be set. By default SSPI does
         * not set this flag, and setting it causes servers with restrictive
         * policy to fail authentication. Given no MS client set this flag
         * by default, neither should we until there is a clear need. We
         * trust our calling applications to do the right thing here.
         * av_flags = MSVAVFLAGS_UNVERIFIED_SPN;
         */

        timestamp = ntlm_timestamp_now();

        retmin = ntlm_encode_target_info(ctx->ntlm,
                                         nb_computer_name,
                                         nb_domain_name,
                                         server_name->data.server.name,
                                         NULL, NULL,
                                         &av_flags, &timestamp,
                                         NULL,
                                         server_name->data.server.spn,
                                         NULL,
                                         &target_info);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        if (gssntlm_role_is_domain_member(ctx)) {
            chal_target_name = nb_domain_name;
            ctx->neg_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
        } else {
            chal_target_name = nb_computer_name;
            ctx->neg_flags |= NTLMSSP_TARGET_TYPE_SERVER;
        }

        retmin = ntlm_encode_chal_msg(ctx->ntlm, ctx->neg_flags,
                                      chal_target_name, &challenge,
                                      &target_info, &ctx->chal_msg);
        if (retmin) {
            set_GSSERR(retmin);
            goto done;
        }

        ctx->stage = NTLMSSP_STAGE_CHALLENGE;

        output_token->value = malloc(ctx->chal_msg.length);
        if (!output_token->value) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        memcpy(output_token->value, ctx->chal_msg.data, ctx->chal_msg.length);
        output_token->length = ctx->chal_msg.length;

        retmaj = GSS_S_CONTINUE_NEEDED;

    } else {
        ctx = (struct gssntlm_ctx *)(*context_handle);

        if (!gssntlm_role_is_server(ctx)) {
            set_GSSERRS(ERR_WRONGCTX, GSS_S_NO_CONTEXT);
            goto done;
        }

        if ((input_token == GSS_C_NO_BUFFER) ||
            (input_token->length == 0)) {
            set_GSSERRS(ERR_NOTOKEN, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        ctx->auth_msg.data = malloc(input_token->length);
        if (!ctx->auth_msg.data) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        memcpy(ctx->auth_msg.data, input_token->value, input_token->length);
        ctx->auth_msg.length = input_token->length;

        retmin = ntlm_decode_msg_type(ctx->ntlm, &ctx->auth_msg, &msg_type);
        if (retmin) {
            set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        if (msg_type != AUTHENTICATE_MESSAGE ||
                ctx->stage != NTLMSSP_STAGE_CHALLENGE) {
            set_GSSERRS(ERR_WRONGMSG, GSS_S_NO_CONTEXT);
            goto done;
        }

        retmin = ntlm_decode_auth_msg(ctx->ntlm, &ctx->auth_msg,
                                      ctx->neg_flags,
                                      &lm_chal_resp, &nt_chal_resp,
                                      &dom_name, &usr_name, &wks_name,
                                      &enc_sess_key, &target_info, &mic);
        if (retmin) {
            set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        if (target_info.length > 0) {
            retmin = ntlm_decode_target_info(ctx->ntlm, &target_info,
                                             NULL, NULL, NULL, NULL,
                                             NULL, NULL, &av_flags,
                                             NULL, NULL, &av_cb);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }
        }

        if ((ctx->neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM) &&
            !(ctx->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
            set_GSSERRS(ERR_BADNEGFLAGS, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        if ((usr_name == NULL) || (usr_name[0] == '\0')) {
            if ((nt_chal_resp.length == 0) &&
                (((lm_chal_resp.length == 1) &&
                  (lm_chal_resp.data[0] == '\0')) ||
                 (lm_chal_resp.length == 0))) {
                /* Anonymous auth */
                /* FIXME: not supported for now */
                set_GSSERR(ERR_NOTSUPPORTED);
                goto done;
            } else {
                set_GSSERR(ERR_NOUSRFOUND);
                goto done;
            }
        } else {

            char useratdom[1024];
            size_t ulen, dlen, uadlen;
            gss_buffer_desc usrname;
            gss_const_key_value_set_t cred_store = GSS_C_NO_CRED_STORE;
            gss_key_value_set_desc cs;
            gss_key_value_element_desc cs_el;

            if (!dom_name) {
                dom_name = strdup("");
                if (!dom_name) {
                    set_GSSERR(ENOMEM);
                    goto done;
                }
            }

            /* Use domain\username format as that allows to pass in
             * enterprise names without the need to escape them */
            ulen = strlen(usr_name);
            dlen = strlen(dom_name);
            if (ulen + dlen + 2 > 1024) {
                set_GSSERR(ERR_NAMETOOLONG);
                goto done;
            }
            uadlen = dlen;
            if (dlen) {
                memcpy(useratdom, dom_name, dlen);
            }

            /* always add the domain separator, this way if the username
             * is an enteprise name (user@email.domain form) it will be
             * correctly recognized by gssntlm_import_name() as such */
            useratdom[uadlen] = '\\';
            uadlen++;

            /* finally add usernmae part */
            memcpy(&useratdom[uadlen], usr_name, ulen);
            uadlen += ulen;
            useratdom[uadlen] = '\0';

            usrname.value = useratdom;
            usrname.length = uadlen;
            retmaj = gssntlm_import_name(&retmin, &usrname,
                                         GSS_C_NT_USER_NAME,
                                         (gss_name_t *)&gss_usrname);
            if (retmaj) goto done;

            if (cred && cred->cred.server.keyfile) {
                cs_el.key = GSS_NTLMSSP_CS_KEYFILE;
                cs_el.value = cred->cred.server.keyfile;
                cs.count = 1;
                cs.elements = &cs_el;
                cred_store = &cs;
            }

            retmaj = gssntlm_acquire_cred_from(&retmin, ctx->external_context,
                                               (gss_name_t)gss_usrname,
                                                GSS_C_INDEFINITE,
                                                GSS_C_NO_OID_SET,
                                                GSS_C_INITIATE,
                                                cred_store,
                                                (gss_cred_id_t *)&usr_cred,
                                                NULL, NULL);
            if (retmaj) goto done;
            /* We can't handle winbind credentials yet */
            if (usr_cred->type != GSSNTLM_CRED_USER &&
                usr_cred->type != GSSNTLM_CRED_EXTERNAL) {
                set_GSSERRS(ERR_NOUSRCRED, GSS_S_DEFECTIVE_CREDENTIAL);
                goto done;
            }

            retmin = gssntlm_copy_name(gss_usrname, &ctx->source_name);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }

            retmaj = gssntlm_srv_auth(&retmin, ctx, usr_cred,
                                      &nt_chal_resp, &lm_chal_resp,
                                      &key_exchange_key);
            if (retmaj) goto done;
        }

        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
            memcpy(encrypted_random_session_key.data, enc_sess_key.data, 16);
            ctx->exported_session_key.length = 16;

            retmin = ntlm_encrypted_session_key(&key_exchange_key,
                                                &encrypted_random_session_key,
                                                &ctx->exported_session_key);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }
        } else {
            ctx->exported_session_key = key_exchange_key;
        }

        /* check if MIC was sent */
        if (av_flags & MSVAVFLAGS_MIC_PRESENT) {
            retmin = ntlm_verify_mic(&ctx->exported_session_key,
                                     &ctx->nego_msg, &ctx->chal_msg,
                                     &ctx->auth_msg, &mic);
            if (retmin) {
                set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
                goto done;
            }
        }

        if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
            uint8_t zero_cb[16] = { 0 };
            if (input_chan_bindings->initiator_addrtype != 0 ||
                input_chan_bindings->initiator_address.length != 0 ||
                input_chan_bindings->acceptor_addrtype != 0 ||
                input_chan_bindings->acceptor_address.length != 0 ||
                input_chan_bindings->application_data.length == 0) {
                set_GSSERRS(ERR_BADARG, GSS_S_BAD_BINDINGS);
                goto done;
            }
            unhashed_cb.length = input_chan_bindings->application_data.length;
            unhashed_cb.data = input_chan_bindings->application_data.value;

            if (av_cb.length && (av_cb.length != 16)) {
                set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
                goto done;
            }
            if (av_cb.length &&
                (memcmp(av_cb.data, zero_cb, 16) != 0)) {
                retmin = ntlm_verify_channel_bindings(&unhashed_cb, &av_cb);
                if (retmin) {
                    set_GSSERRS(retmin, GSS_S_DEFECTIVE_TOKEN);
                    goto done;
/* This flag has been introduced only recently in MIT krb5 */
#ifdef GSS_C_CHANNEL_BOUND_FLAG
                } else {
                    ctx->gss_flags |= GSS_C_CHANNEL_BOUND_FLAG;
#endif /* GSS_C_CHANNEL_BOUND_FLAG */
                }
            }
        }

        if (ctx->neg_flags & (NTLMSSP_NEGOTIATE_SIGN |
                                NTLMSSP_NEGOTIATE_SEAL)) {
            retmin = ntlm_signseal_keys(ctx->neg_flags, false,
                                        &ctx->exported_session_key,
                                        &ctx->crypto_state);
            if (retmin) {
                set_GSSERR(retmin);
                goto done;
            }
        }

        if (src_name) {
            retmaj = gssntlm_duplicate_name(&retmin,
                                            (gss_name_t)&ctx->source_name,
                                            src_name);
            if (retmaj) goto done;
        }

        ctx->stage = NTLMSSP_STAGE_DONE;
        ctx->expiration_time = time(NULL) + MAX_CHALRESP_LIFETIME;
        ctx->int_flags |= NTLMSSP_CTX_FLAG_ESTABLISHED;
        set_GSSERRS(0, GSS_S_COMPLETE);
    }

done:

    if ((retmaj != GSS_S_COMPLETE) &&
        (retmaj != GSS_S_CONTINUE_NEEDED)) {
        gssntlm_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&ctx, NULL);
    } else {
        if (mech_type) *mech_type = discard_const(&gssntlm_oid);
        if (ret_flags) *ret_flags = ctx->gss_flags;
        if (time_rec) *time_rec = GSS_C_INDEFINITE;
    }
    *context_handle = (gss_ctx_id_t)ctx;
    gssntlm_release_name(&tmpmin, (gss_name_t *)&server_name);
    gssntlm_release_name(&tmpmin, (gss_name_t *)&gss_usrname);
    gssntlm_release_cred(&tmpmin, (gss_cred_id_t *)&usr_cred);
    safefree(nb_computer_name);
    safefree(nb_domain_name);
    safefree(usr_name);
    safefree(dom_name);
    safefree(wks_name);
    ntlm_free_buffer_data(&nt_chal_resp);
    ntlm_free_buffer_data(&lm_chal_resp);
    ntlm_free_buffer_data(&enc_sess_key);
    ntlm_free_buffer_data(&target_info);

    return GSSERR();
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

    ctx = (struct gssntlm_ctx *)context_handle;
    if (!ctx) {
        return GSSERRS(ERR_NOARG, GSS_S_NO_CONTEXT);
    }

    if (src_name) {
        retmaj = gssntlm_duplicate_name(&retmin,
                                        (gss_name_t)&ctx->source_name,
                                        src_name);
        if (retmaj) goto done;
    }

    if (targ_name) {
        retmaj = gssntlm_duplicate_name(&retmin,
                                        (gss_name_t)&ctx->target_name,
                                        targ_name);
        if (retmaj) goto done;
    }

    if (mech_type) {
        *mech_type = discard_const(&gssntlm_oid);
    }

    if (ctx_flags) {
        *ctx_flags = ctx->gss_flags;
    }

    if (locally_initiated) {
        if (gssntlm_role_is_client(ctx)) {
            *locally_initiated = 1;
        } else {
            *locally_initiated = 0;
        }
    }

    if (ctx->int_flags & NTLMSSP_CTX_FLAG_ESTABLISHED) {
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

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

gss_OID_desc set_seq_num_oid = {
    GSS_NTLMSSP_SET_SEQ_NUM_OID_LENGTH,
    discard_const(GSS_NTLMSSP_SET_SEQ_NUM_OID_STRING)
};

uint32_t gssntlm_set_seq_num(uint32_t *minor_status,
                             struct gssntlm_ctx *ctx,
                             const gss_buffer_t value)
{
    uint32_t retmin;
    uint32_t retmaj;

    if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
        if (value->length != 4) {
            return GSSERRS(ERR_BADARG, GSS_S_FAILURE);
        }
        memcpy(&ctx->crypto_state.recv.seq_num,
               value->value, value->length);
        ctx->crypto_state.send.seq_num = ctx->crypto_state.recv.seq_num;
    } else {
        return GSSERRS(ERR_WRONGCTX, GSS_S_FAILURE);
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

gss_OID_desc reset_crypto_oid = {
    GSS_NTLMSSP_RESET_CRYPTO_OID_LENGTH,
    discard_const(GSS_NTLMSSP_RESET_CRYPTO_OID_STRING)
};

uint32_t gssntlm_reset_crypto(uint32_t *minor_status,
                              struct gssntlm_ctx *ctx,
                              const gss_buffer_t value)
{
    uint32_t retmin;
    uint32_t retmaj;

    if (value->length != 4) {
        return GSSERRS(ERR_BADARG, GSS_S_FAILURE);
    }

    /* reset crypto state */
    if (ctx->neg_flags & (NTLMSSP_NEGOTIATE_SIGN |
                            NTLMSSP_NEGOTIATE_SEAL)) {
        uint32_t val;

        memcpy(&val, value->value, value->length);

        /* A val of 1 means we want to reset the verifier handle,
         * which is the receive handle for NTLM, otherwise we reset
         * the send handle. */
        retmin = ntlm_reset_rc4_state(ctx->neg_flags, (val == 1),
                                      &ctx->exported_session_key,
                                      &ctx->crypto_state);
        if (retmin) {
            return GSSERRS(retmin, GSS_S_FAILURE);
        }
    }

    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_set_sec_context_option(uint32_t *minor_status,
                                        gss_ctx_id_t *context_handle,
                                        const gss_OID desired_object,
                                        const gss_buffer_t value)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmin;
    uint32_t retmaj;

    if (context_handle == NULL || *context_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (desired_object == GSS_C_NO_OID) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    ctx = (struct gssntlm_ctx *)*context_handle;

    /* set seq num */
    if (gss_oid_equal(desired_object, &set_seq_num_oid)) {
        return gssntlm_set_seq_num(minor_status, ctx, value);
    } else if (gss_oid_equal(desired_object, &reset_crypto_oid)) {
        return gssntlm_reset_crypto(minor_status, ctx, value);
    }

    return GSSERRS(ERR_BADARG, GSS_S_UNAVAILABLE);
}

gss_OID_desc spnego_req_mic_oid = {
    GSS_SPNEGO_REQUIRE_MIC_OID_LENGTH,
    discard_const(GSS_SPNEGO_REQUIRE_MIC_OID_STRING)
};

uint32_t gssntlm_spnego_req_mic(uint32_t *minor_status,
                                struct gssntlm_ctx *ctx,
                                gss_buffer_set_t *data_set)
{
    gss_buffer_desc mic_buf;
    uint32_t retmin;
    uint32_t retmaj;
    uint32_t tmpmin;
    uint8_t mic_set;

    /* the simple fact the spnego layer is asking means it can handle
     * forcing mechlistMIC if we add a MIC to the Authenticate packet.
     * We expect this to be called before the authenticate token is
     * generated to set this flag ... */
    ctx->int_flags |= NTLMSSP_CTX_FLAG_SPNEGO_CAN_MIC;

    /* ... and then again after, in which case if we actually did add
     * a MIC we can tell spnego to add a mechlistMIC */
    if (ctx->int_flags & NTLMSSP_CTX_FLAG_AUTH_WITH_MIC) {
        mic_set = 1;
    } else {
        mic_set = 0;
    }

    mic_buf.value = &mic_set;
    mic_buf.length = sizeof(mic_set);

    retmaj = gss_add_buffer_set_member(&retmin, &mic_buf, data_set);
    if (retmaj != GSS_S_COMPLETE) {
        (void)gss_release_buffer_set(&tmpmin, data_set);
    }

    return GSSERRS(retmin, retmaj);
}

static const gss_OID_desc sasl_ssf_oid = {
    11, discard_const("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f")
};

static uint32_t gssntlm_sasl_ssf(uint32_t *minor_status,
                                 struct gssntlm_ctx *ctx,
                                 gss_buffer_set_t *data_set)
{
    uint32_t retmin;
    uint32_t retmaj;
    uint32_t tmpmin;
    gss_buffer_desc ssf_buf;
    uint32_t ssf = 0;

    /* Handwaving a bit here but this is what SSF is all about */
    if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
        if (ctx->neg_flags & NTLMSSP_NEGOTIATE_128) {
            /* Technically we use RC4 with a 128 bit key, but we
             * consider the RC4 strenght degraded so we assign
             * it a value of 64, this is consistent with what
             * the krb5 mechanism does for the Rc4-HMAC enctype */
            ssf = 64;
        } else if (ctx->neg_flags & NTLMSSP_NEGOTIATE_56) {
            ssf = 56;
        } else {
            ssf = 40;
        }
    } else if (ctx->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
        ssf = 1;
    }

    ssf = htobe32(ssf);
    ssf_buf.value = &ssf;
    ssf_buf.length = 4;

    retmaj = gss_add_buffer_set_member(&retmin, &ssf_buf, data_set);
    if (retmaj != GSS_S_COMPLETE) {
        (void)gss_release_buffer_set(&tmpmin, data_set);
    }

    return GSSERRS(retmin, retmaj);
}

static uint32_t gssntlm_sspi_session_key(uint32_t *minor_status,
                                         struct gssntlm_ctx *ctx,
                                         gss_buffer_set_t *data_set)
{
    uint32_t retmin;
    uint32_t retmaj;
    uint32_t tmpmin;
    gss_buffer_desc session_key_buf;

    if (ctx->exported_session_key.length == 0) {
      return GSSERRS(ERR_NOTAVAIL, GSS_S_UNAVAILABLE);
    }

    session_key_buf.length = ctx->exported_session_key.length;
    session_key_buf.value = ctx->exported_session_key.data;

    retmaj = gss_add_buffer_set_member(&retmin, &session_key_buf,  data_set);
    if (retmaj != GSS_S_COMPLETE) {
        (void)gss_release_buffer_set(&tmpmin, data_set);
    }
    return GSSERRS(retmin, retmaj);
}

uint32_t gssntlm_inquire_sec_context_by_oid(uint32_t *minor_status,
	                                    const gss_ctx_id_t context_handle,
	                                    const gss_OID desired_object,
	                                    gss_buffer_set_t *data_set)
{
    struct gssntlm_ctx *ctx;
    uint32_t retmin;
    uint32_t retmaj;

    if (context_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (desired_object == GSS_C_NO_OID) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (!data_set) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    ctx = (struct gssntlm_ctx *)context_handle;
    *data_set = GSS_C_NO_BUFFER_SET;

    if (gss_oid_equal(desired_object, &spnego_req_mic_oid)) {
        return gssntlm_spnego_req_mic(minor_status, ctx, data_set);
    } else if (gss_oid_equal(desired_object, &sasl_ssf_oid)){
        return gssntlm_sasl_ssf(minor_status, ctx, data_set);
    } else if (gss_oid_equal(desired_object, GSS_C_INQ_SSPI_SESSION_KEY)) {
      return gssntlm_sspi_session_key(minor_status, ctx, data_set);
    }

    return GSSERRS(ERR_NOTSUPPORTED, GSS_S_UNAVAILABLE);
}
