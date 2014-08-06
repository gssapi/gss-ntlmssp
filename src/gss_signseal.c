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

uint32_t gssntlm_get_mic(uint32_t *minor_status,
                         gss_ctx_id_t context_handle,
                         gss_qop_t qop_req,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer signature;
    uint32_t retmaj, retmin;

    *minor_status = 0;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return retmaj;
    }
    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSS_S_BAD_QOP;
    }
    if (!message_buffer->value || message_buffer->length == 0) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
        /* must regenerate seal key */
        retmin = ntlm_seal_regen(&ctx->send.seal_key,
                                 &ctx->send.seal_handle,
                                 ctx->send.seq_num);
        if (retmin) {
            *minor_status = retmin;
            return GSS_S_FAILURE;
        }
    }

    message_token->value = malloc(16);
    if (!message_token->value) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    message_token->length = 16;

    message.data = message_buffer->value;
    message.length = message_buffer->length;
    signature.data = message_token->value;
    signature.length = message_token->length;
    retmin = ntlm_sign(&ctx->send.sign_key, ctx->send.seq_num,
                       ctx->send.seal_handle, ctx->neg_flags,
                       &message, &signature);
    if (retmin) {
        *minor_status = retmin;
        safefree(message_token->value);
        return GSS_S_FAILURE;
    }

    if (!(ctx->gss_flags & GSS_C_DATAGRAM_FLAG)) {
        /* increment seq_num upon succesful signature */
        ctx->send.seq_num++;
    }

    return GSS_S_COMPLETE;
}

uint32_t gssntlm_verify_mic(uint32_t *minor_status,
                            gss_ctx_id_t context_handle,
                            gss_buffer_t message_buffer,
                            gss_buffer_t message_token,
                            gss_qop_t *qop_state)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    uint8_t token[16];
    struct ntlm_buffer signature = { token, 16 };
    uint32_t retmaj, retmin;

    *minor_status = 0;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return retmaj;
    }
    if (!message_buffer->value || message_buffer->length == 0) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (qop_state) {
        *qop_state = GSS_C_QOP_DEFAULT;
    }

    if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
        /* must regenerate seal key */
        retmin = ntlm_seal_regen(&ctx->recv.seal_key,
                                 &ctx->recv.seal_handle,
                                 ctx->recv.seq_num);
        if (retmin) {
            *minor_status = retmin;
            return GSS_S_FAILURE;
        }
    }

    message.data = message_buffer->value;
    message.length = message_buffer->length;
    retmin = ntlm_sign(&ctx->recv.sign_key, ctx->recv.seq_num,
                       ctx->recv.seal_handle, ctx->neg_flags,
                       &message, &signature);
    if (retmin) {
        *minor_status = retmin;
        return GSS_S_FAILURE;
    }

    if (memcmp(signature.data, message_token->value, 16) != 0) {
        return GSS_S_BAD_SIG;
    }

    if (!(ctx->gss_flags & GSS_C_DATAGRAM_FLAG)) {
        /* increment seq_num upon succesful signature */
        ctx->recv.seq_num++;
    }

    return GSS_S_COMPLETE;
}

uint32_t gssntlm_wrap(uint32_t *minor_status,
                      gss_ctx_id_t context_handle,
                      int conf_req_flag,
                      gss_qop_t qop_req,
                      gss_buffer_t input_message_buffer,
                      int *conf_state,
                      gss_buffer_t output_message_buffer)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer output;
    struct ntlm_buffer signature;
    uint32_t retmaj, retmin;

    *minor_status = 0;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return retmaj;
    }
    if (qop_req != GSS_C_QOP_DEFAULT) {
        return GSS_S_BAD_QOP;
    }
    if (!input_message_buffer->value || input_message_buffer->length == 0) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (conf_state) {
        *conf_state = 0;
    }

    if (conf_req_flag == 0) {
        /* ignore, always seal */
    }

    if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
        /* must regenerate seal key */
        retmin = ntlm_seal_regen(&ctx->send.seal_key,
                                 &ctx->send.seal_handle,
                                 ctx->send.seq_num);
        if (retmin) {
            *minor_status = retmin;
            return GSS_S_FAILURE;
        }
    }

    output_message_buffer->value = malloc(input_message_buffer->length + 16);
    if (!output_message_buffer->value) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    output_message_buffer->length = input_message_buffer->length + 16;

    message.data = input_message_buffer->value;
    message.length = input_message_buffer->length;
    output.data = output_message_buffer->value;
    output.length = input_message_buffer->length;
    signature.data = &output.data[input_message_buffer->length];
    signature.length = 16;
    retmin = ntlm_seal(ctx->send.seal_handle, ctx->neg_flags,
                       &ctx->send.sign_key, ctx->send.seq_num,
                       &message, &output, &signature);
    if (retmin) {
        *minor_status = retmin;
        safefree(output_message_buffer->value);
        return GSS_S_FAILURE;
    }

    if (!(ctx->gss_flags & GSS_C_DATAGRAM_FLAG)) {
        /* increment seq_num upon succesful encryption */
        ctx->send.seq_num++;
    }
    return GSS_S_COMPLETE;
}

uint32_t gssntlm_unwrap(uint32_t *minor_status,
                        gss_ctx_id_t context_handle,
                        gss_buffer_t input_message_buffer,
                        gss_buffer_t output_message_buffer,
                        int *conf_state,
                        gss_qop_t *qop_state)
{
    struct gssntlm_ctx *ctx;
    struct ntlm_buffer message;
    struct ntlm_buffer output;
    uint8_t sig[16];
    struct ntlm_buffer signature = { sig, 16 };
    uint32_t retmaj, retmin;

    *minor_status = 0;

    ctx = (struct gssntlm_ctx *)context_handle;
    retmaj = gssntlm_context_is_valid(ctx, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        return retmaj;
    }
    if (!input_message_buffer->value || input_message_buffer->length == 0) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (conf_state) {
        *conf_state = 0;
    }
    if (qop_state) {
        *qop_state = GSS_C_QOP_DEFAULT;
    }

    if (ctx->gss_flags & GSS_C_DATAGRAM_FLAG) {
        /* must regenerate seal key */
        retmin = ntlm_seal_regen(&ctx->recv.seal_key,
                                 &ctx->recv.seal_handle,
                                 ctx->send.seq_num);
        if (retmin) {
            *minor_status = retmin;
            return GSS_S_FAILURE;
        }
    }

    output_message_buffer->value = malloc(input_message_buffer->length - 16);
    if (!output_message_buffer->value) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    output_message_buffer->length = input_message_buffer->length - 16;

    message.data = input_message_buffer->value;
    message.length = input_message_buffer->length;
    output.data = output_message_buffer->value;
    output.length = output_message_buffer->length;
    retmin = ntlm_unseal(ctx->recv.seal_handle, ctx->neg_flags,
                         &ctx->recv.sign_key, ctx->recv.seq_num,
                         &message, &output, &signature);
    if (retmin) {
        *minor_status = retmin;
        safefree(output_message_buffer->value);
        return GSS_S_FAILURE;
    }

    if (memcmp(&message.data[output.length], signature.data, 16) != 0) {
        safefree(output_message_buffer->value);
        return GSS_S_BAD_SIG;
    }

    if (!(ctx->gss_flags & GSS_C_DATAGRAM_FLAG)) {
        /* increment seq_num upon succesful encryption */
        ctx->recv.seq_num++;
    }
    return GSS_S_COMPLETE;
}
