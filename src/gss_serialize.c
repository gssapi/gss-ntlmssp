/* Copyright 2013 Simo Sorce <simo@samba.org>, see COPYING for license */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gssapi_ntlmssp.h"
#include "gss_ntlmssp.h"

/* each integer in the export format is a little endian integer */
#pragma pack(push, 1)
struct relmem {
    uint32_t ptr;
    uint32_t len;
};

struct export_attrs {
    uint16_t count;
    /* for each count there is a pair of name/value buffers
     * that we'll pack in a single buffer */
    struct relmem buffers;
};

struct export_name {
    uint8_t type;
    struct relmem dom_or_spn;
    struct relmem name;
    struct export_attrs attrs;
};

struct export_keys {
    struct relmem sign_key;
    struct relmem seal_key;
    struct relmem rc4_state;
    uint32_t seq_num;
};

#define EXPORT_CTX_VER 0x0005
struct export_ctx {
    uint16_t version;
    uint8_t role;
    uint8_t stage;
    uint8_t sec_req;

    struct relmem workstation;

    struct relmem nego_msg;
    struct relmem chal_msg;
    struct relmem auth_msg;

    struct export_name source;
    struct export_name target;

    uint8_t server_chal[8];

    uint32_t gss_flags;
    uint32_t neg_flags;

    struct relmem exported_session_key;
    struct export_keys send;
    struct export_keys recv;

    uint8_t int_flags;
    uint64_t expration_time;

    uint8_t data[];
};
#pragma pack(pop)

#define EXP_CTX_CLIENT 1
#define EXP_CTX_SERVER 2
#define EXP_CTX_DOMSRV 3
#define EXP_CTX_DOMCTR 4
#define EXP_STG_INIT 1
#define EXP_STG_NEGO 2
#define EXP_STG_CHAL 3
#define EXP_STG_AUTH 4
#define EXP_STG_DONE 5
#define EXP_NAME_NONE 0
#define EXP_NAME_ANON 1
#define EXP_NAME_USER 2
#define EXP_NAME_SERV 3

#define INC_EXP_SIZE 0x001000 /* 4K */
#define MAX_EXP_SIZE 0x100000 /* 1M */

#define NEW_SIZE(s, n) \
    ((((s) + (n) + (INC_EXP_SIZE-1)) / INC_EXP_SIZE) * INC_EXP_SIZE)

struct export_state {
    uint8_t *exp_struct;
    size_t exp_size;
    size_t exp_data;
    size_t exp_len;
};

#define RELMEM_PTR(state, rm) \
    ((state)->exp_struct + (state)->exp_data + (rm)->ptr)

#define RELMEM_ZERO(rm) \
    memset((rm), 0, sizeof(struct relmem))

static int export_data_allocate(struct export_state *state,
                                size_t length, struct relmem *rm)
{
    size_t new_size;
    void *tmp;

    if (length > MAX_EXP_SIZE) {
        return E2BIG;
    }

    if (length > state->exp_size - state->exp_len) {
        new_size = NEW_SIZE(state->exp_len, length);
        if ((new_size < state->exp_size) || new_size > MAX_EXP_SIZE) {
            return E2BIG;
        }
        tmp = realloc(state->exp_struct, new_size);
        if (!tmp) {
            return ENOMEM;
        }
        state->exp_struct = tmp;
        state->exp_size = new_size;
    }

    rm->ptr = state->exp_len - state->exp_data;
    rm->len = length;
    state->exp_len += length;

    return 0;
}

static int export_data_buffer(struct export_state *state,
                              void *data, size_t length,
                              struct relmem *rm)
{
    int ret;

    if (length == 0) {
        RELMEM_ZERO(rm);
        return 0;
    }

    ret = export_data_allocate(state, length, rm);
    if (ret) return ret;

    memcpy(RELMEM_PTR(state, rm), data, length);
    return 0;
}

static int export_attrs(struct export_state *state,
                        struct gssntlm_name_attribute *attrs,
                        struct export_attrs *exp_attrs)
{
    size_t count = gssntlm_get_attrs_count(attrs);
    size_t ptr_array_size = 0;
    int ret;

    if (count == 0) return 0;
    if (count > UINT16_MAX) return E2BIG;

    exp_attrs->count = count;

    /* reserve data space in state->exp_struct for pointers */
    ptr_array_size = count * 2 * sizeof(struct relmem);
    ret = export_data_allocate(state, ptr_array_size, &exp_attrs->buffers);
    if (ret) return ret;

    /* exp_attrs->buffers may be reallocated as part of data structure
     * expansion in export_data_buffer() so we need to recompute the
     * buffers pointer after each use of export_data_buffer */
    for (size_t i = 0; i < count; i++) {
        struct relmem *buffers;
        struct relmem buffer;
        /* name */
        ret = export_data_buffer(state, attrs[i].attr_name,
                                 strlen(attrs[i].attr_name), &buffer);
        if (ret) return ret;
        buffers = (struct relmem *)RELMEM_PTR(state, &exp_attrs->buffers);
        memcpy(&buffers[i * 2], &buffer, sizeof(struct relmem));
        /* value */
        ret = export_data_buffer(state, attrs[i].attr_value.value,
                                 attrs[i].attr_value.length, &buffer);
        if (ret) return ret;
        buffers = (struct relmem *)RELMEM_PTR(state, &exp_attrs->buffers);
        memcpy(&buffers[i * 2 + 1], &buffer, sizeof(struct relmem));
    }

    return 0;
}

static int export_name(struct export_state *state,
                       struct gssntlm_name *name,
                       struct export_name *exp_name)
{
    int ret;

    memset(exp_name, 0, sizeof(struct export_name));

    switch (name->type) {
    case GSSNTLM_NAME_NULL:
        break;
    case GSSNTLM_NAME_ANON:
        exp_name->type = EXP_NAME_ANON;
        break;
    case GSSNTLM_NAME_USER:
        exp_name->type = EXP_NAME_USER;
        if (name->data.user.domain) {
            ret = export_data_buffer(state, name->data.user.domain,
                                     strlen(name->data.user.domain),
                                     &exp_name->dom_or_spn);
            if (ret) {
                return ret;
            }
        }
        if (name->data.user.name) {
            ret = export_data_buffer(state, name->data.user.name,
                                     strlen(name->data.user.name),
                                     &exp_name->name);
            if (ret) {
                return ret;
            }
        }
        break;
    case GSSNTLM_NAME_SERVER:
        exp_name->type = EXP_NAME_SERV;
        if (name->data.server.spn) {
            ret = export_data_buffer(state, name->data.server.spn,
                                     strlen(name->data.server.spn),
                                     &exp_name->dom_or_spn);
            if (ret) {
                return ret;
            }
        }
        if (name->data.server.name) {
            ret = export_data_buffer(state, name->data.server.name,
                                     strlen(name->data.server.name),
                                     &exp_name->name);
            if (ret) {
                return ret;
            }
        }
        break;
    default:
        return EINVAL;
    }
    return export_attrs(state, name->attrs, &exp_name->attrs);
}

static int export_keys(struct export_state *state,
                       struct ntlm_signseal_handle *keys,
                       struct export_keys *exp_keys)
{
    uint8_t buf[258*sizeof(uint32_t)];
    struct ntlm_buffer out = { .data=buf, .length=sizeof(buf) };
    int ret;

    memset(exp_keys, 0, sizeof(struct export_keys));

    if (keys->sign_key.length > 0) {
        ret = export_data_buffer(state,
                                 keys->sign_key.data,
                                 keys->sign_key.length,
                                 &exp_keys->sign_key);
        if (ret) return ret;
    }

    if (keys->seal_key.length > 0) {
        ret = export_data_buffer(state,
                                 keys->seal_key.data,
                                 keys->seal_key.length,
                                 &exp_keys->seal_key);
        if (ret) return ret;
    }

    if (keys->seal_handle) {
        ret = RC4_EXPORT(keys->seal_handle, &out);
        if (ret) return ret;
        ret = export_data_buffer(state, buf, sizeof(buf),
                                 &exp_keys->rc4_state);
        safezero(buf, sizeof(buf));
        if (ret) return ret;
    }

    exp_keys->seq_num = htole32(keys->seq_num);

    return 0;
}

uint32_t gssntlm_export_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_buffer_t interprocess_token)
{
    struct gssntlm_ctx *ctx;
    struct export_state state = { 0 };
    struct export_ctx ectx = { 0 };
    uint64_t expiration;
    uint32_t retmaj;
    uint32_t retmin;
    int ret;

    if (context_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (interprocess_token == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    ctx = (struct gssntlm_ctx *)*context_handle;
    if (ctx == NULL) return GSSERRS(ERR_BADARG, GSS_S_NO_CONTEXT);

    if (ctx->expiration_time && ctx->expiration_time < time(NULL)) {
        return GSSERRS(ERR_EXPIRED, GSS_S_CONTEXT_EXPIRED);
    }

    /* we want to leave space to add the basic context structure in the buffer
     * however we want a memory stable structure we can refernce via memory
     * pointers while we run export functions for all the "static" context
     * data, so we allocate space but we use a stack allocated struct until
     * the very end. */
    state.exp_size = NEW_SIZE(0, sizeof(struct export_ctx));
    state.exp_struct = malloc(state.exp_size);
    if (!state.exp_struct) {
        set_GSSERR(ENOMEM);
        goto done;
    }
    state.exp_data = (uint8_t *)&ectx.data - (uint8_t *)&ectx;
    state.exp_len = state.exp_data;

    ectx.version = htole16(EXPORT_CTX_VER);

    switch(ctx->role) {
    case GSSNTLM_CLIENT:
        ectx.role = EXP_CTX_CLIENT;
        break;
    case GSSNTLM_SERVER:
        ectx.role = EXP_CTX_SERVER;
        break;
    case GSSNTLM_DOMAIN_SERVER:
        ectx.role = EXP_CTX_DOMSRV;
        break;
    case GSSNTLM_DOMAIN_CONTROLLER:
        ectx.role = EXP_CTX_DOMCTR;
        break;
    }

    switch(ctx->stage) {
    case NTLMSSP_STAGE_INIT:
        ectx.stage = EXP_STG_INIT;
        break;
    case NTLMSSP_STAGE_NEGOTIATE:
        ectx.stage = EXP_STG_NEGO;
        break;
    case NTLMSSP_STAGE_CHALLENGE:
        ectx.stage = EXP_STG_CHAL;
        break;
    case NTLMSSP_STAGE_AUTHENTICATE:
        ectx.stage = EXP_STG_AUTH;
        break;
    case NTLMSSP_STAGE_DONE:
        ectx.stage = EXP_STG_DONE;
        break;
    }

    ectx.sec_req = ctx->sec_req;

    if (!ctx->workstation) {
        RELMEM_ZERO(&ectx.workstation);
    } else {
        ret = export_data_buffer(&state, ctx->workstation,
                                 strlen(ctx->workstation),
                                 &ectx.workstation);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
    }

    if (ctx->nego_msg.length > 0) {
        ret = export_data_buffer(&state,
                                 ctx->nego_msg.data,
                                 ctx->nego_msg.length,
                                 &ectx.nego_msg);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
    } else {
        RELMEM_ZERO(&ectx.nego_msg);
    }

    if (ctx->chal_msg.length > 0) {
        ret = export_data_buffer(&state,
                                 ctx->chal_msg.data,
                                 ctx->chal_msg.length,
                                 &ectx.chal_msg);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
    } else {
        RELMEM_ZERO(&ectx.chal_msg);
    }

    if (ctx->auth_msg.length > 0) {
        ret = export_data_buffer(&state,
                                 ctx->auth_msg.data,
                                 ctx->auth_msg.length,
                                 &ectx.auth_msg);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
    } else {
        RELMEM_ZERO(&ectx.auth_msg);
    }

    ret = export_name(&state, &ctx->source_name, &ectx.source);
    if (ret) {
        set_GSSERR(ret);
        goto done;
    }

    ret = export_name(&state, &ctx->target_name, &ectx.target);
    if (ret) {
        set_GSSERR(ret);
        goto done;
    }

    memcpy(ectx.server_chal, ctx->server_chal, 8);

    ectx.gss_flags = htole32(ctx->gss_flags);
    ectx.neg_flags = htole32(ctx->neg_flags);

    ret = export_data_buffer(&state,
                             ctx->exported_session_key.data,
                             ctx->exported_session_key.length,
                             &ectx.exported_session_key);
    if (ret) {
        set_GSSERR(ret);
        goto done;
    }

    ret = export_keys(&state, &ctx->crypto_state.send, &ectx.send);
    if (ret) {
        set_GSSERR(ret);
        goto done;
    }

    ret = export_keys(&state, &ctx->crypto_state.recv, &ectx.recv);
    if (ret) {
        set_GSSERR(ret);
        goto done;
    }

    ectx.int_flags = ctx->int_flags;

    expiration = ctx->expiration_time;
    ectx.expration_time = htole64(expiration);

    /* finally copy ectx into the allocated buffer */
    memcpy(state.exp_struct, &ectx, state.exp_data);

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj) {
        free(state.exp_struct);
    } else {
        uint32_t min;
        interprocess_token->value = state.exp_struct;
        interprocess_token->length = state.exp_len;

        /* Invalidate the current context once successfully exported */
        gssntlm_delete_sec_context(&min, context_handle, NULL);
    }
    return GSSERR();
}

static uint32_t import_data_buffer(uint32_t *minor_status,
                                   struct export_state *state,
                                   uint8_t **dest, size_t *len, bool alloc,
                                   struct relmem *rm, bool str)
{
    uint32_t retmaj;
    uint32_t retmin;
    void *ptr;

    if (str && !alloc) {
        return EINVAL;
    }

    if (rm->len == 0) {
        if (alloc) {
            *dest = NULL;
        }
        set_GSSERRS(0, GSS_S_COMPLETE);
        goto done;
    }

    if (state->exp_data + rm->ptr + rm->len > state->exp_len) {
        set_GSSERRS(0, GSS_S_DEFECTIVE_TOKEN);
        goto done;
    }
    ptr = RELMEM_PTR(state, rm);
    if (alloc) {
        if (str) {
            *dest = (uint8_t *)strndup((const char *)ptr, rm->len);
        } else {
            *dest = malloc(rm->len);
            if (*dest) {
                memcpy(*dest, ptr, rm->len);
            }
        }
        if (!*dest) {
            set_GSSERR(ENOMEM);
            goto done;
        }
    } else {
        if (!*len) {
            set_GSSERR(ERR_BADARG);
            goto done;
        }
        if (rm->len > *len) {
            set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }
        memcpy(*dest, ptr, rm->len);
    }
    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj == GSS_S_COMPLETE) {
        if (len) *len = rm->len;
    }
    return GSSERR();
}

static uint32_t import_attrs(uint32_t *minor_status,
                             struct export_state *state,
                             struct export_attrs *attrs,
                             struct gssntlm_name_attribute **imp_attrs)
{
    struct gssntlm_name_attribute *a;
    uint32_t retmaj = GSS_S_COMPLETE;
    uint32_t retmin = 0;
    uint8_t *cursor;

    if (attrs->count == 0) goto done;

    a = calloc(attrs->count + 1, sizeof(struct gssntlm_name_attribute));
    if (a == NULL) {
        set_GSSERR(ENOMEM);
        goto done;
    }
    *imp_attrs = a;

    cursor = RELMEM_PTR(state, &attrs->buffers);

    for (size_t i = 0; i < attrs->count; i++) {
        struct relmem name;
        struct relmem value;
        memcpy(&name, cursor, sizeof(struct relmem));
        cursor += sizeof(struct relmem);
        memcpy(&value, cursor, sizeof(struct relmem));
        cursor += sizeof(struct relmem);
        retmaj = import_data_buffer(&retmin, state,
                                    (uint8_t **)&a[i].attr_name,
                                    NULL, true, &name, true);
        if (retmaj != GSS_S_COMPLETE) goto done;
        retmaj = import_data_buffer(&retmin, state,
                                    (uint8_t **)&a[i].attr_value.value,
                                    &a[i].attr_value.length,
                                    true, &value, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

static uint32_t import_name(uint32_t *minor_status,
                            struct export_state *state,
                            struct export_name *name,
                            struct gssntlm_name *imp_name)
{
    uint32_t retmaj;
    uint32_t retmin;
    uint8_t *dest;

    switch (name->type) {
    case EXP_NAME_NONE:
        memset(imp_name, 0, sizeof(struct gssntlm_name));
        break;

    case EXP_NAME_ANON:
        memset(imp_name, 0, sizeof(struct gssntlm_name));
        imp_name->type = GSSNTLM_NAME_ANON;
        break;

    case EXP_NAME_USER:
        imp_name->type = GSSNTLM_NAME_USER;
        dest = NULL;
        if (name->dom_or_spn.len > 0) {
            retmaj = import_data_buffer(&retmin, state,
                                     &dest, NULL, true,
                                     &name->dom_or_spn, true);
            if (retmaj != GSS_S_COMPLETE) goto done;
        }
        imp_name->data.user.domain = (char *)dest;
        dest = NULL;
        if (name->name.len > 0) {
            retmaj = import_data_buffer(&retmin, state,
                                     &dest, NULL, true,
                                     &name->name, true);
            if (retmaj != GSS_S_COMPLETE) goto done;
        }
        imp_name->data.user.name = (char *)dest;
        break;

    case EXP_NAME_SERV:
        imp_name->type = GSSNTLM_NAME_SERVER;
        dest = NULL;
        if (name->dom_or_spn.len > 0) {
            retmaj = import_data_buffer(&retmin, state,
                                     &dest, NULL, true,
                                     &name->dom_or_spn, true);
            if (retmaj != GSS_S_COMPLETE) goto done;
        }
        imp_name->data.server.spn = (char *)dest;
        dest = NULL;
        if (name->name.len > 0) {
            retmaj = import_data_buffer(&retmin, state,
                                     &dest, NULL, true,
                                     &name->name, true);
            if (retmaj != GSS_S_COMPLETE) goto done;
        }
        imp_name->data.server.name = (char *)dest;
        break;

    default:
        set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
        break;
    }

    retmaj = import_attrs(minor_status, state, &name->attrs, &imp_name->attrs);
    if (retmaj != GSS_S_COMPLETE) goto done;

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

static uint32_t import_keys(uint32_t *minor_status,
                            struct export_state *state,
                            struct export_keys *keys,
                            struct ntlm_signseal_handle *imp_keys)
{
    struct ntlm_buffer in;
    uint8_t *dest;
    uint32_t retmaj;
    uint32_t retmin;
    int ret;

    if (keys->sign_key.len > 0) {
        imp_keys->sign_key.length = 16; /* buf max size */
        dest = imp_keys->sign_key.data;
        retmaj = import_data_buffer(&retmin, state,
                                 &dest, &imp_keys->sign_key.length,
                                 false, &keys->sign_key, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        memset(&imp_keys->sign_key, 0, sizeof(struct ntlm_key));
    }

    if (keys->seal_key.len > 0) {
        imp_keys->seal_key.length = 16; /* buf max size */
        dest = imp_keys->seal_key.data;
        retmaj = import_data_buffer(&retmin, state,
                                 &dest, &imp_keys->seal_key.length,
                                 false, &keys->seal_key, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        memset(&imp_keys->seal_key, 0, sizeof(struct ntlm_key));
    }

    if (keys->rc4_state.len > 0) {
        retmaj = import_data_buffer(&retmin, state,
                                 &in.data, &in.length, true,
                                 &keys->rc4_state, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
        ret = RC4_IMPORT(&imp_keys->seal_handle, &in);
        safezero(in.data, in.length);
        safefree(in.data);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
    } else {
        imp_keys->seal_handle = NULL;
    }

    imp_keys->seq_num = le32toh(keys->seq_num);

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

uint32_t gssntlm_import_sec_context(uint32_t *minor_status,
                                    gss_buffer_t interprocess_token,
                                    gss_ctx_id_t *context_handle)
{
    struct gssntlm_ctx *ctx = NULL;
    struct export_state state;
    struct export_ctx *ectx;
    uint8_t *dest;
    uint64_t time;
    uint32_t retmaj;
    uint32_t retmin;

    if (interprocess_token == NULL) {
        return GSSERRS(0, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (interprocess_token->length < sizeof(struct export_ctx)) {
        return GSSERRS(0, GSS_S_DEFECTIVE_TOKEN);
    }

    if (context_handle == NULL) {
        return GSSERRS(0, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    ctx = calloc(1, sizeof(struct gssntlm_ctx));
    if (!ctx) {
        set_GSSERR(ENOMEM);
        goto done;
    }
    retmin = ntlm_init_ctx(&ctx->ntlm);
    if (retmin) {
        set_GSSERR(retmin);
        goto done;
    }

    state.exp_struct = interprocess_token->value;
    state.exp_len = interprocess_token->length;
    ectx = (struct export_ctx *)state.exp_struct;
    state.exp_data = (uint8_t *)ectx->data - (uint8_t *)ectx;

    if (ectx->version != le16toh(EXPORT_CTX_VER)) {
        set_GSSERRS(0, GSS_S_DEFECTIVE_TOKEN);
        goto done;
    }

    switch (ectx->role) {
    case EXP_CTX_CLIENT:
        ctx->role = GSSNTLM_CLIENT;
        break;
    case EXP_CTX_SERVER:
        ctx->role = GSSNTLM_SERVER;
        break;
    case EXP_CTX_DOMSRV:
        ctx->role = GSSNTLM_DOMAIN_SERVER;
        break;
    case EXP_CTX_DOMCTR:
        ctx->role = GSSNTLM_DOMAIN_CONTROLLER;
        break;
    default:
        set_GSSERRS(0, GSS_S_DEFECTIVE_TOKEN);
        goto done;
    }

    switch (ectx->stage) {
    case EXP_STG_INIT:
        ctx->stage = NTLMSSP_STAGE_INIT;
        break;
    case EXP_STG_NEGO:
        ctx->stage = NTLMSSP_STAGE_NEGOTIATE;
        break;
    case EXP_STG_CHAL:
        ctx->stage = NTLMSSP_STAGE_CHALLENGE;
        break;
    case EXP_STG_AUTH:
        ctx->stage = NTLMSSP_STAGE_AUTHENTICATE;
        break;
    case EXP_STG_DONE:
        ctx->stage = NTLMSSP_STAGE_DONE;
        break;
    default:
        set_GSSERRS(0, GSS_S_DEFECTIVE_TOKEN);
        goto done;
    }

    ctx->sec_req = ectx->sec_req;

    dest = NULL;
    if (ectx->workstation.len > 0) {
        retmaj = import_data_buffer(&retmin, &state, &dest, NULL,
                                 true, &ectx->workstation, true);
        if (retmaj != GSS_S_COMPLETE) goto done;
    }
    ctx->workstation = (char *)dest;

    if (ectx->nego_msg.len > 0) {
        retmaj = import_data_buffer(&retmin, &state,
                                 &ctx->nego_msg.data, &ctx->nego_msg.length,
                                 true, &ectx->nego_msg, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        ctx->nego_msg.data = NULL;
        ctx->nego_msg.length = 0;
    }

    if (ectx->chal_msg.len > 0) {
        retmaj = import_data_buffer(&retmin, &state,
                                 &ctx->chal_msg.data, &ctx->chal_msg.length,
                                 true, &ectx->chal_msg, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        ctx->chal_msg.data = NULL;
        ctx->chal_msg.length = 0;
    }

    if (ectx->auth_msg.len > 0) {
        retmaj = import_data_buffer(&retmin, &state,
                                 &ctx->auth_msg.data, &ctx->auth_msg.length,
                                 true, &ectx->auth_msg, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        ctx->auth_msg.data = NULL;
        ctx->auth_msg.length = 0;
    }

    retmaj = import_name(&retmin, &state,
                      &ectx->source, &ctx->source_name);
    if (retmaj != GSS_S_COMPLETE) goto done;

    retmaj = import_name(&retmin, &state,
                      &ectx->target, &ctx->target_name);
    if (retmaj != GSS_S_COMPLETE) goto done;

    memcpy(ctx->server_chal, ectx->server_chal, 8);

    ctx->gss_flags = le32toh(ectx->gss_flags);
    ctx->neg_flags = le32toh(ectx->neg_flags);

    if (ectx->exported_session_key.len > 0) {
        ctx->exported_session_key.length = 16; /* buf max size */
        dest = ctx->exported_session_key.data;
        retmaj = import_data_buffer(&retmin, &state, &dest,
                                 &ctx->exported_session_key.length,
                                 false, &ectx->exported_session_key, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
    } else {
        memset(&ctx->exported_session_key, 0, sizeof(struct ntlm_key));
    }

    retmaj = import_keys(&retmin, &state,
                      &ectx->send, &ctx->crypto_state.send);
    if (retmaj != GSS_S_COMPLETE) goto done;

    retmaj = import_keys(&retmin, &state,
                      &ectx->recv, &ctx->crypto_state.recv);
    if (retmaj != GSS_S_COMPLETE) goto done;

    /* We need to restoer also the general crypto status flags */
    ctx->crypto_state.ext_sec =
        (ctx->neg_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
    ctx->crypto_state.datagram =
        (ctx->neg_flags & NTLMSSP_NEGOTIATE_DATAGRAM);

    ctx->int_flags = ectx->int_flags;

    time = le64toh(ectx->expration_time);
    ctx->expiration_time = time;

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj == GSS_S_COMPLETE) {
        *context_handle = (gss_ctx_id_t)ctx;
    } else {
        uint32_t min;
        gssntlm_delete_sec_context(&min, (gss_ctx_id_t *)&ctx, NULL);
    }
    return GSSERR();
}

#define EXPORT_CRED_VER 0x0002

#pragma pack(push, 1)
struct export_cred {
    uint16_t version;
    uint16_t type;

    struct export_name name;    /* user or server name */
    struct relmem nt_hash;      /* empty for dummy or server */
    struct relmem lm_hash;      /* empty for dummy or server */
    struct relmem keyfile;
    uint8_t ext_cached;

    uint8_t data[];
};
#pragma pack(pop)

#define EXP_CRED_NONE 0
#define EXP_CRED_ANON 1
#define EXP_CRED_USER 2
#define EXP_CRED_SERVER 3
#define EXP_CRED_EXTERNAL 4

uint32_t gssntlm_export_cred(uint32_t *minor_status,
                             gss_cred_id_t cred_handle,
                             gss_buffer_t token)
{
    struct gssntlm_cred *cred;
    struct export_state state = { 0 };
    struct export_cred ecred = { 0 };
    uint32_t retmaj;
    uint32_t retmin;
    int ret;

    if (token == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    cred = (struct gssntlm_cred *)cred_handle;
    if (cred_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_NO_CRED);
    }

    /* we want to leave space to add the basic creds structure in the buffer
     * however we want a memory stable structure we can refernce via memory
     * pointers while we run export functions for all the "static" context
     * data, so we allocate space but we use a stack allocated struct until
     * the very end. */
    state.exp_size = NEW_SIZE(0, sizeof(struct export_cred));
    state.exp_struct = calloc(1, state.exp_size);
    if (!state.exp_struct) {
        set_GSSERR(ENOMEM);
        goto done;
    }
    state.exp_data = (uint8_t *)&ecred.data - (uint8_t *)&ecred;
    state.exp_len = state.exp_data;

    ecred.version = htole16(EXPORT_CRED_VER);

    switch (cred->type) {
    case GSSNTLM_CRED_NONE:
        ecred.type = EXP_CRED_NONE;
        break;
    case GSSNTLM_CRED_ANON:
        ecred.type = EXP_CRED_ANON;
        break;
    case GSSNTLM_CRED_USER:
        ecred.type = EXP_CRED_USER;

        ret = export_name(&state, &cred->cred.user.user, &ecred.name);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }

        ret = export_data_buffer(&state,
                                 cred->cred.user.nt_hash.data,
                                 cred->cred.user.nt_hash.length,
                                 &ecred.nt_hash);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }

        ret = export_data_buffer(&state,
                                 cred->cred.user.lm_hash.data,
                                 cred->cred.user.lm_hash.length,
                                 &ecred.lm_hash);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
        break;
    case GSSNTLM_CRED_SERVER:
        ecred.type = EXP_CRED_SERVER;

        ret = export_name(&state, &cred->cred.server.name, &ecred.name);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }

        if (cred->cred.server.keyfile) {
            ret = export_data_buffer(&state,
                                     cred->cred.server.keyfile,
                                     strlen(cred->cred.server.keyfile),
                                     &ecred.keyfile);
            if (ret) {
                set_GSSERR(ret);
                goto done;
            }
        }
        break;
    case GSSNTLM_CRED_EXTERNAL:
        ecred.type = EXP_CRED_EXTERNAL;

        ret = export_name(&state, &cred->cred.external.user, &ecred.name);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
        if (cred->cred.external.creds_in_cache) {
            ecred.ext_cached = 1;
        }
        break;

    }

    /* finally copy ecred into the allocated buffer */
    memcpy(state.exp_struct, &ecred, state.exp_data);

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj) {
        free(state.exp_struct);
    } else {
        token->value = state.exp_struct;
        token->length = state.exp_len;
    }
    return GSSERR();
}

uint32_t gssntlm_import_cred(uint32_t *minor_status,
                             gss_buffer_t token,
                             gss_cred_id_t *cred_handle)
{
    struct gssntlm_cred *cred;
    struct export_state state = { 0 };
    struct export_cred *ecred;
    uint32_t retmaj;
    uint32_t retmin;

    if (token == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (token->length < sizeof(struct export_cred)) {
        return GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
    }

    if (cred_handle == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    cred = calloc(1, sizeof(struct gssntlm_cred));
    if (!cred) {
        set_GSSERR(ENOMEM);
        goto done;
    }

    state.exp_struct = token->value;
    state.exp_len = token->length;
    ecred = (struct export_cred *)state.exp_struct;
    state.exp_data = (char *)ecred->data - (char *)ecred;

    if (ecred->version != le16toh(EXPORT_CRED_VER)) {
        set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
        goto done;
    }

    switch (ecred->type) {
    case EXP_CRED_NONE:
        cred->type = GSSNTLM_CRED_NONE;
        break;
    case EXP_CRED_ANON:
        cred->type = GSSNTLM_CRED_ANON;
        break;
    case EXP_CRED_USER:
        cred->type = GSSNTLM_CRED_USER;
        retmaj = import_name(&retmin, &state, &ecred->name,
                          &cred->cred.user.user);
        if (retmaj != GSS_S_COMPLETE) goto done;

        if (ecred->nt_hash.len > 16 || ecred->lm_hash.len > 16) {
            set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
            goto done;
        }

        retmaj = import_data_buffer(&retmin, &state,
                                 (uint8_t **)&cred->cred.user.nt_hash.data,
                                 &cred->cred.user.nt_hash.length,
                                 false, &ecred->nt_hash, false);
        if (retmaj != GSS_S_COMPLETE) goto done;

        retmaj = import_data_buffer(&retmin, &state,
                                 (uint8_t **)&cred->cred.user.lm_hash.data,
                                 &cred->cred.user.lm_hash.length,
                                 false, &ecred->lm_hash, false);
        if (retmaj != GSS_S_COMPLETE) goto done;
        break;
    case EXP_CRED_SERVER:
        cred->type = GSSNTLM_CRED_SERVER;
        retmaj = import_name(&retmin, &state, &ecred->name,
                          &cred->cred.server.name);
        if (retmaj != GSS_S_COMPLETE) goto done;
        if (ecred->keyfile.len > 0) {
            retmaj = import_data_buffer(&retmin, &state,
                                        (uint8_t **)&cred->cred.server.keyfile,
                                        NULL, true, &ecred->keyfile, true);
            if (retmaj != GSS_S_COMPLETE) goto done;
        }
        break;
    case EXP_CRED_EXTERNAL:
        cred->type = GSSNTLM_CRED_EXTERNAL;
        retmaj = import_name(&retmin, &state, &ecred->name,
                          &cred->cred.external.user);
        if (retmaj != GSS_S_COMPLETE) goto done;
        cred->cred.external.creds_in_cache = (ecred->ext_cached == 1);
        break;
    default:
        set_GSSERRS(ERR_BADARG, GSS_S_DEFECTIVE_TOKEN);
        break;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj == GSS_S_COMPLETE) {
        *cred_handle = (gss_cred_id_t)cred;
    } else {
        uint32_t min;
        gssntlm_release_cred(&min, (gss_cred_id_t *)&cred);
    }
    return GSSERR();
}
