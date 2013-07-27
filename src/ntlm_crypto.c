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


/* This File implements the NTLM protocol as specified by:
 *      [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
 *
 * Additional cross checking with:
 * http://davenport.sourceforge.net/ntlm.html
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <unicase.h>
#include <uniconv.h>

#include "ntlm.h"
#include "crypto.h"

/* lm response, v1 or v2 */
#pragma pack(push, 1)
union wire_lm_response {
    struct {
        uint8_t resp[24];
    } v1;
    struct {
        uint8_t resp[16];
        uint8_t cli_chal[8];
    } v2;
};
#pragma pack(pop)

/* ntlm response, v1 or v2 */
#pragma pack(push, 1)
union wire_ntlm_response {
    struct {
        uint8_t resp[24];
    } v1;
    struct {
        uint8_t resp[16];
        uint8_t cli_chal[];
    } v2;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wire_ntlmv2_cli_chal {
    uint8_t resp_version;
    uint8_t hi_resp_version;
    uint8_t zero_6[6];
    uint64_t timestamp;
    uint8_t client_chal[8];
    uint8_t zero_4[4];
    uint8_t target_info[];
        /* NOTE: the target_info array must terminate with 4 zero bytes.
         * This is consistent with just copying the target_info array
         * returned in the challenge message as the last AV_PAIR there is
         * always MSV_AV_EOL which happens to be 4 bytes of zeros */
};
#pragma pack(pop)

/* the max username is 20 chars, max NB domain len is 15, so 128 should be
 * plenty including conversion to UTF8 using max lenght for each code point
 */
#define MAX_USER_DOM_LEN 512


int NTOWFv1(const char *password, struct ntlm_key *result)
{
    struct ntlm_buffer payload;
    struct ntlm_buffer hash;
    char *retstr;
    size_t out;
    size_t len;
    int ret;

    len = strlen(password);
    retstr = u8_conv_to_encoding("UCS-2LE", iconveh_error,
                                 (const uint8_t *)password, len,
                                 NULL, NULL, &out);
    if (!retstr) return ERR_CRYPTO;

    payload.data = (uint8_t *)retstr;
    payload.length = out;
    hash.data = result->data;
    hash.length = result->length;

    ret = MD4_HASH(&payload, &hash);
    free(retstr);
    return ret;
}

#define DES_CONST "KGS!@#$%"
int LMOWFv1(const char *password, struct ntlm_key *result)
{
    struct ntlm_buffer key;
    struct ntlm_buffer plain;
    struct ntlm_buffer cipher;
    char upcased[15];
    char *retstr;
    size_t out;
    size_t len;
    int ret;

    if (result->length != 16) return EINVAL;

    len = strlen(password);
    if (len > 14) return ERANGE;

    out = 15;
    retstr = (char *)u8_toupper((const uint8_t *)password, len,
                                NULL, NULL, (uint8_t *)upcased, &out);
    if (!retstr) return ERR_CRYPTO;
    if (retstr != upcased) {
        free(retstr);
        ret = EINVAL;
    }
    memset(&upcased[len], 0, 15 - len);

    /* part1 */
    key.data = (uint8_t *)upcased;
    key.length = 7;
    plain.data = discard_const(DES_CONST);
    plain.length = 8;
    cipher.data = result->data;
    cipher.length = 8;
    ret = WEAK_DES(&key, &plain, &cipher);
    if (ret) return ret;

    /* part2 */
    key.data = (uint8_t *)&upcased[7];
    key.length = 7;
    plain.data = discard_const(DES_CONST);
    plain.length = 8;
    cipher.data = &result->data[8];
    cipher.length = 8;
    return WEAK_DES(&key, &plain, &cipher);
}

int ntlm_compute_nt_response(struct ntlm_key *nt_key, bool ext_sec,
                             uint8_t server_chal[8], uint8_t client_chal[8],
                             struct ntlm_buffer *nt_response)
{
    struct ntlm_buffer key = { nt_key->data, nt_key->length };
    struct ntlm_buffer payload;
    struct ntlm_buffer result;
    uint8_t buf1[16];
    uint8_t buf2[16];
    int ret;

    memcpy(buf1, server_chal, 8);
    if (ext_sec) {
        memcpy(&buf1[8], client_chal, 8);
        payload.data = buf1;
        payload.length = 16;
        result.data = buf2;
        result.length = 16;
        ret = MD5_HASH(&payload, &result);
        if (ret) return ret;
        memcpy(buf1, result.data, 8);
    }
    payload.data = buf1;
    payload.length = 8;

    return DESL(&key, &payload, nt_response);
}

int ntlm_compute_lm_response(struct ntlm_key *lm_key, bool ext_sec,
                             uint8_t server_chal[8], uint8_t client_chal[8],
                             struct ntlm_buffer *lm_response)
{
    struct ntlm_buffer key = { lm_key->data, lm_key->length };
    struct ntlm_buffer payload = { server_chal, 8 };

    if (ext_sec) {
        memcpy(lm_response->data, client_chal, 8);
        memset(&lm_response->data[8], 0, 16);
        return 0;
    }
    return DESL(&key, &payload, lm_response);
}

int ntlm_session_base_key(struct ntlm_key *nt_key,
                          struct ntlm_key *session_base_key)
{
    struct ntlm_buffer payload = { nt_key->data, nt_key->length };
    struct ntlm_buffer hash = { session_base_key->data,
                                session_base_key->length };

    return MD4_HASH(&payload, &hash);
}

int KXKEY(struct ntlm_ctx *ctx,
          bool ext_sec,
          bool neg_lm_key,
          bool non_nt_sess_key,
          uint8_t server_chal[8],
          struct ntlm_key *lm_key,
          struct ntlm_key *session_base_key,
          struct ntlm_buffer *lm_response,
          struct ntlm_key *key_exchange_key)
{
    struct ntlm_buffer payload;
    struct ntlm_buffer result;
    struct ntlm_buffer key;
    uint8_t buf[16];
    int ret = 0;

    if (ext_sec) {
        key.data = session_base_key->data;
        key.length = session_base_key->length;
        memcpy(buf, server_chal, 8);
        memcpy(&buf[8], lm_response->data, 8);
        payload.data = buf;
        payload.length = 16;
        result.data = key_exchange_key->data;
        result.length = key_exchange_key->length;
        ret = HMAC_MD5(&key, &payload, &result);
    } else if (neg_lm_key) {
        payload.data = lm_response->data;
        payload.length = 8;
        key.data = lm_key->data;
        key.length = 7;
        result.data = key_exchange_key->data;
        result.length = 8;
        ret = WEAK_DES(&key, &payload, &result);
        if (ret) return ret;
        buf[0] = lm_key->data[7];
        memset(&buf[1], 0xbd, 6);
        key.data = buf;
        result.data = &key_exchange_key->data[8];
        result.length = 8;
        ret = WEAK_DES(&key, &payload, &result);
    } else if (non_nt_sess_key) {
        memcpy(key_exchange_key->data, lm_key, 8);
        memset(&key_exchange_key->data[8], 0, 8);
    } else {
        memcpy(key_exchange_key->data, session_base_key->data, 16);
    }
    return ret;
}

int NTOWFv2(struct ntlm_ctx *ctx, struct ntlm_key *nt_hash,
            const char *user, const char *domain, struct ntlm_key *result)
{
    struct ntlm_buffer key = { nt_hash->data, nt_hash->length };
    struct ntlm_buffer hmac = { result->data, result->length };
    struct ntlm_buffer payload;
    uint8_t upcased[MAX_USER_DOM_LEN];
    uint8_t *retstr;
    size_t offs;
    size_t out;
    size_t len;
    int ret;

    len = strlen(user);
    out = MAX_USER_DOM_LEN;
    retstr = u8_toupper((const uint8_t *)user, len,
                        NULL, NULL, upcased, &out);
    if (!retstr) return ERR_CRYPTO;
    offs = out;

    len = strlen(domain);
    /*
    out = MAX_USER_DOM_LEN - offs;
    retstr = u8_toupper((const uint8_t *)domain, len,
                        NULL, NULL, &upcased[offs], &out);
    if (!retstr) return ERR_CRYPTO;
    offs += out;
    */
    memcpy(&upcased[offs], domain, len);
    offs += len;

    retstr = (uint8_t *)u8_conv_to_encoding("UCS-2LE", iconveh_error,
                                            upcased, offs, NULL, NULL, &out);
    if (!retstr) return ERR_CRYPTO;

    payload.data = (uint8_t *)retstr;
    payload.length = out;

    ret = HMAC_MD5(&key, &payload, &hmac);
    free(retstr);
    return ret;
}

int ntlmv2_compute_nt_response(struct ntlm_key *ntlmv2_key,
                               uint8_t server_chal[8], uint8_t client_chal[8],
                               uint64_t timestamp,
                               struct ntlm_buffer *target_info,
                               struct ntlm_buffer *nt_response)
{
    union wire_ntlm_response *nt_resp = NULL;
    struct wire_ntlmv2_cli_chal *r;
    struct ntlm_buffer key = { ntlmv2_key->data, ntlmv2_key->length };
    struct ntlm_buffer payload;
    struct ntlm_buffer nt_proof;
    size_t r_len;
    int ret;

    /* add additional 4 0s trailing target_info */
    r_len = sizeof(struct wire_ntlmv2_cli_chal) + target_info->length + 4;
    nt_resp = calloc(1, sizeof(nt_resp->v2) + r_len);
    if (!nt_resp) return ENOMEM;

    r = (struct wire_ntlmv2_cli_chal *)nt_resp->v2.cli_chal;
    r->resp_version = 1;
    r->hi_resp_version = 1;
    r->timestamp = htole64(timestamp);
    memcpy(r->client_chal, client_chal, 8);
    memcpy(r->target_info, target_info->data, target_info->length);

    /* use nt_resp as a buffer to calculate the NT proof as they share
     * the cli_chal part */
    payload.data = &nt_resp->v2.resp[8];
    payload.length = 8 + r_len;
    memcpy(payload.data, server_chal, 8);
    nt_proof.data = nt_resp->v2.resp;
    nt_proof.length = 16;
    ret = HMAC_MD5(&key, &payload, &nt_proof);

    if (ret) {
        safefree(nt_resp);
    } else {
        nt_response->data = (uint8_t *)nt_resp;
        nt_response->length = 16 + r_len;
    }
    return ret;
}

int ntlmv2_compute_lm_response(struct ntlm_key *ntlmv2_key,
                               uint8_t server_chal[8], uint8_t client_chal[8],
                               struct ntlm_buffer *lm_response)
{
    union wire_lm_response *lm_resp = NULL;
    struct ntlm_buffer key = { ntlmv2_key->data, ntlmv2_key->length };
    uint8_t payload_buf[16];
    struct ntlm_buffer payload = { payload_buf, 16 };
    struct ntlm_buffer lm_proof;
    int ret;

    /* now caluclate the LM Proof */
    lm_resp = malloc(sizeof(union wire_lm_response));
    if (!lm_resp) {
        ret = ENOMEM;
        goto done;
    }

    memcpy(payload.data, server_chal, 8);
    memcpy(&payload.data[8], client_chal, 8);
    lm_proof.data = lm_resp->v2.resp;
    lm_proof.length = 16;
    ret = HMAC_MD5(&key, &payload, &lm_proof);

done:
    if (ret) {
        safefree(lm_resp);
    } else {
        memcpy(lm_resp->v2.cli_chal, client_chal, 8);

        lm_response->data = (uint8_t *)lm_resp;
        lm_response->length = 24;
    }
    return ret;
}

int ntlmv2_session_base_key(struct ntlm_key *ntlmv2_key,
                            struct ntlm_buffer *nt_response,
                            struct ntlm_key *session_base_key)
{
    struct ntlm_buffer key = { ntlmv2_key->data, ntlmv2_key->length };
    struct ntlm_buffer hmac = { session_base_key->data,
                                session_base_key->length };

    if (session_base_key->length != 16) return EINVAL;

    return HMAC_MD5(&key, nt_response, &hmac);
}

int ntlm_exported_session_key(struct ntlm_key *key_exchange_key,
                              bool key_exch,
                              struct ntlm_key *exported_session_key)
{
    struct ntlm_buffer nonce;

    if (!key_exch) {
        *exported_session_key = *key_exchange_key;
        return 0;
    }

    exported_session_key->length = 16;
    nonce.data = exported_session_key->data;
    nonce.length = exported_session_key->length;
    return RAND_BUFFER(&nonce);
}

int ntlm_encrypted_session_key(struct ntlm_key *key,
                               struct ntlm_key *in, struct ntlm_key *out)
{
    struct ntlm_buffer _key = { key->data, key->length };
    struct ntlm_buffer data = { in->data, in->length };
    struct ntlm_buffer result = { out->data, out->length };

    return RC4K(&_key, NTLM_CIPHER_ENCRYPT, &data, &result);
}

static int ntlm_key_derivation_function(struct ntlm_key *key,
                                        const char *magic_constant,
                                        struct ntlm_key *derived_key)
{
    uint8_t buf[80]; /* key + constant is never larger than 80 */
    struct ntlm_buffer payload = { buf, 0 };
    struct ntlm_buffer result = { derived_key->data, 16 };
    size_t len;
    int ret;

    if (key->length > 16) return ERR_CRYPTO;
    len = strlen(magic_constant);
    if (len > 64) return ERR_CRYPTO;

    payload.length = key->length;
    memcpy(payload.data, key->data, key->length);
    memcpy(&payload.data[payload.length], magic_constant, len);
    payload.length += len;

    ret = MD5_HASH(&payload, &result);
    if (ret == 0) {
        derived_key->length = 16;
    }
    return ret;
}

#define NTLM_MODE_CLIENT true
#define NTLM_MODE_SERVER false

static int ntlm_signkey(uint32_t flags, bool mode,
                        struct ntlm_key *random_session_key,
                        struct ntlm_key *signing_key)
{
    const char *mc;

    if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        if (mode == NTLM_MODE_CLIENT) {
            mc = "session key to client-to-server signing key magic constant";
        } else {
            mc = "session key to server-to-client signing key magic constant";
        }
        return ntlm_key_derivation_function(random_session_key,
                                            mc, signing_key);
    } else {
        signing_key->length = 0;
    }
    return 0;
}

static int ntlm_sealkey(uint32_t flags, bool mode,
                        struct ntlm_key *random_session_key,
                        struct ntlm_key *sealing_key)
{
    struct ntlm_key key;
    const char *mc;

    if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        if (flags & NTLMSSP_NEGOTIATE_128) {
            key.length = 16;
        } else if (flags & NTLMSSP_NEGOTIATE_56) {
            key.length = 7;
        } else {
            key.length = 5;
        }
        memcpy(key.data, random_session_key->data, key.length);

        if (mode == NTLM_MODE_CLIENT) {
            mc = "session key to client-to-server sealing key magic constant";
        } else {
            mc = "session key to server-to-client sealing key magic constant";
        }

        return ntlm_key_derivation_function(&key, mc, sealing_key);

    } else if (flags & NTLMSSP_NEGOTIATE_LM_KEY) {
        if (flags & NTLMSSP_NEGOTIATE_56) {
            memcpy(sealing_key->data, random_session_key->data, 7);
            sealing_key->data[7] = 0xA0;
        } else {
            memcpy(sealing_key->data, random_session_key->data, 5);
            sealing_key->data[5] = 0xE5;
            sealing_key->data[6] = 0x38;
            sealing_key->data[7] = 0xB0;
        }
        sealing_key->length = 8;
    } else {
        *sealing_key = *random_session_key;
    }
    return 0;
}

int ntlm_signseal_keys(uint32_t flags, bool client,
                       struct ntlm_key *random_session_key,
                       struct ntlm_key *sign_send_key,
                       struct ntlm_key *sign_recv_key,
                       struct ntlm_key *seal_send_key,
                       struct ntlm_key *seal_recv_key,
                       struct ntlm_rc4_handle **seal_send_handle,
                       struct ntlm_rc4_handle **seal_recv_handle)
{
    struct ntlm_buffer rc4_key;
    bool mode;
    int ret;

    /* send key */
    mode = client ? NTLM_MODE_CLIENT : NTLM_MODE_SERVER;
    ret = ntlm_signkey(flags, mode, random_session_key, sign_send_key);
    if (ret) return ret;
    /* recv key */
    mode = client ? NTLM_MODE_SERVER : NTLM_MODE_CLIENT;
    ret = ntlm_signkey(flags, mode, random_session_key, sign_recv_key);
    if (ret) return ret;

    /* send key */
    mode = client ? NTLM_MODE_CLIENT : NTLM_MODE_SERVER;
    ret = ntlm_sealkey(flags, mode, random_session_key, seal_send_key);
    if (ret) return ret;
    /* recv key */
    mode = client ? NTLM_MODE_SERVER : NTLM_MODE_CLIENT;
    ret = ntlm_sealkey(flags, mode, random_session_key, seal_recv_key);
    if (ret) return ret;

    rc4_key.data = seal_send_key->data;
    rc4_key.length = seal_send_key->length;
    ret = RC4_INIT(&rc4_key, NTLM_CIPHER_ENCRYPT, seal_send_handle);
    if (ret) return ret;

    rc4_key.data = seal_recv_key->data;
    rc4_key.length = seal_recv_key->length;
    ret = RC4_INIT(&rc4_key, NTLM_CIPHER_DECRYPT, seal_recv_handle);
    if (ret) return ret;

    return 0;
}

int ntlmv2_verify_nt_response(struct ntlm_buffer *nt_response,
                              struct ntlm_key *ntlmv2_key,
                              uint8_t server_chal[8])
{
    union wire_ntlm_response *nt_resp = NULL;
    struct ntlm_buffer key = { ntlmv2_key->data, ntlmv2_key->length };
    uint8_t proof[16];
    struct ntlm_buffer nt_proof = { proof, 16 };
    struct ntlm_buffer payload;
    int ret;

    if (nt_response->length < 24) return EINVAL;

    nt_resp = (union wire_ntlm_response *)nt_response->data;

    payload.length = 8;
    payload.data = server_chal;

    payload.length = nt_response->length - 8;
    payload.data = malloc(payload.length);
    if (!payload.data) return ENOMEM;
    memcpy(payload.data, server_chal, 8);
    memcpy(&payload.data[8], nt_resp->v2.cli_chal, payload.length - 8);

    ret = HMAC_MD5(&key, &payload, &nt_proof);

    if (ret) goto done;

    ret = EINVAL;
    if (memcmp(nt_resp->v2.resp, proof, 16) == 0) {
        ret = 0;
    }

done:
    safefree(payload.data);
    return ret;
}

int ntlmv2_verify_lm_response(struct ntlm_buffer *lm_response,
                              struct ntlm_key *ntlmv2_key,
                              uint8_t server_chal[8])
{
    struct ntlm_buffer key = { ntlmv2_key->data, ntlmv2_key->length };
    union wire_lm_response *lm_resp = NULL;
    uint8_t payload_buf[16];
    struct ntlm_buffer payload = { payload_buf, 16 };
    uint8_t proof[16];
    struct ntlm_buffer lm_proof = { proof, 16 };
    int ret;

    if (lm_response->length != 24) return EINVAL;

    /* now caluclate the LM Proof */
    lm_resp = (union wire_lm_response *)lm_response->data;

    memcpy(payload.data, server_chal, 8);
    memcpy(&payload.data[8], lm_resp->v2.cli_chal, 8);
    ret = HMAC_MD5(&key, &payload, &lm_proof);

    if (ret) return ret;

    if (memcmp(lm_resp->v2.resp, proof, 16) == 0) return 0;

    return EINVAL;
}
