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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "crypto.h"

int RAND_BUFFER(struct ntlm_buffer *random)
{
    int ret;

    ret = RAND_bytes(random->data, random->length);
    if (ret != 1) {
        return ERR_CRYPTO;
    }
    return 0;
}

int HMAC_MD5(struct ntlm_buffer *key,
             struct ntlm_buffer *payload,
             struct ntlm_buffer *result)
{
    HMAC_CTX hmac_ctx;
    unsigned int len;
    int ret = 0;

    if (result->length != 16) return EINVAL;

    HMAC_CTX_init(&hmac_ctx);

    ret = HMAC_Init_ex(&hmac_ctx, key->data, key->length, EVP_md5(), NULL);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = HMAC_Update(&hmac_ctx, payload->data, payload->length);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = HMAC_Final(&hmac_ctx, result->data, &len);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = 0;

done:
    HMAC_CTX_cleanup(&hmac_ctx);
    return ret;
}



static int mdx_hash(const EVP_MD *type,
                    struct ntlm_buffer *payload,
                    struct ntlm_buffer *result)
{
    EVP_MD_CTX ctx;
    unsigned int len;
    int ret;

    if (result->length != 16) return EINVAL;

    EVP_MD_CTX_init(&ctx);
    ret = EVP_DigestInit_ex(&ctx, type, NULL);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = EVP_DigestUpdate(&ctx, payload->data, payload->length);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = EVP_DigestFinal_ex(&ctx, result->data, &len);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = 0;

done:
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}

int MD4_HASH(struct ntlm_buffer *payload,
             struct ntlm_buffer *result)
{
    return mdx_hash(EVP_md4(), payload, result);
}

int MD5_HASH(struct ntlm_buffer *payload,
             struct ntlm_buffer *result)
{
    return mdx_hash(EVP_md5(), payload, result);
}

struct ntlm_rc4_handle {
    EVP_CIPHER_CTX ctx;
};

int RC4_INIT(struct ntlm_buffer *rc4_key,
             enum ntlm_cipher_mode mode,
             struct ntlm_rc4_handle **out)
{
    struct ntlm_rc4_handle *handle;
    int enc;
    int ret;

    handle = malloc(sizeof(struct ntlm_rc4_handle));
    if (!handle) return ENOMEM;

    switch (mode) {
    case NTLM_CIPHER_ENCRYPT:
        enc = 1;
        break;
    case NTLM_CIPHER_DECRYPT:
        enc = 0;
        break;
    default:
        enc = -1;
    }

    EVP_CIPHER_CTX_init(&handle->ctx);
    ret = EVP_CipherInit_ex(&handle->ctx, EVP_rc4(), NULL, NULL, NULL, enc);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }
    ret = EVP_CIPHER_CTX_set_key_length(&handle->ctx, rc4_key->length);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }
    ret = EVP_CipherInit_ex(&handle->ctx, NULL, NULL, rc4_key->data, NULL, -1);
    if (ret == 0) {
        ret = ERR_CRYPTO;
        goto done;
    }

    ret = 0;

done:
    if (ret) {
        EVP_CIPHER_CTX_cleanup(&handle->ctx);
        safefree(handle);
    }
    *out = handle;
    return ret;
}

int RC4_UPDATE(struct ntlm_rc4_handle *handle,
               struct ntlm_buffer *in, struct ntlm_buffer *out)
{
    int outl = 0;
    int ret = 0;
    int err;

    if (out->length < in->length) return EINVAL;

    err = EVP_CipherUpdate(&handle->ctx,
                           out->data, &outl, in->data, in->length);
    if (err != 1) ret = ERR_CRYPTO;
    if (outl > out->length) ret = ERR_CRYPTO;

    out->length = outl;
    return ret;
}

void RC4_FREE(struct ntlm_rc4_handle **handle)
{
    if (!handle) return;
    EVP_CIPHER_CTX_cleanup(&(*handle)->ctx);
    safefree(*handle);
}

int RC4K(struct ntlm_buffer *key,
         enum ntlm_cipher_mode mode,
         struct ntlm_buffer *payload,
         struct ntlm_buffer *result)
{
    struct ntlm_rc4_handle *handle;
    int ret;

    if (result->length < payload->length) return EINVAL;

    ret = RC4_INIT(key, mode, &handle);
    if (ret) return ret;

    ret = RC4_UPDATE(handle, payload, result);

    RC4_FREE(&handle);
    return ret;
}

