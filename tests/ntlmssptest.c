/*
   GSS-NTLM

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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "../src/ntlm.h"

const char *hex_to_str_8(uint8_t *d)
{
    static char hex_to_str_8_str[17];
    snprintf(hex_to_str_8_str, 17,
             "%02x %02x %02x %02x %02x %02x %02x %02x",
             d[0], d[1], d[2],  d[3],  d[4],  d[5],  d[6],  d[7]);
    return hex_to_str_8_str;
}

const char *hex_to_str_16(uint8_t *d)
{
    static char hex_to_str_16_str[33];
    snprintf(hex_to_str_16_str, 33,
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             d[0], d[1], d[2],  d[3],  d[4],  d[5],  d[6],  d[7],
             d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    return hex_to_str_16_str;
}

const char *hex_to_dump(uint8_t *d, size_t s)
{
    static char hex_to_dump_str[1024];
    char format[] = " %02x";
    size_t t, i, j, p;

    if (s > 256) t = 256;
    else t = s;

    snprintf(hex_to_dump_str, 4, format, d[0]);
    for (i = 1, p = 3; i < t; i++) {
        snprintf(&hex_to_dump_str[p], 4, format, d[i]);
        p += 3;
        if (((i + 1) % 16) == 0) {
            hex_to_dump_str[p++] = ' ';
            hex_to_dump_str[p++] = ' ';
            for (j = i - 15; j < i; j++) {
                if (isalnum(d[j])) hex_to_dump_str[p++] = d[j];
                else hex_to_dump_str[p++] = '.';
            }
            hex_to_dump_str[p++] = '\n';
            hex_to_dump_str[p] = '\0';
        }
    }
    if (t < s) {
        snprintf(&hex_to_dump_str[p], 7, " [..]\n");
    } else if (hex_to_dump_str[p] != '\n') {
        hex_to_dump_str[p] = '\n';
        hex_to_dump_str[p + 1] = '\0';
    }
    return hex_to_dump_str;
}

/* Test Data as per para 4.2 of MS-NLMP */
char *T_User = "User";
char *T_UserDom = "Domain";
char *T_Passwd = "Password";
char *T_Server_Name = "Server";
char *T_Workstation = "COMPUTER";
uint8_t T_RandomSessionKey[] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};
uint64_t T_time = 0;
uint8_t T_ClientChallenge[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
uint8_t T_ServerChallenge[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

/* NTLMv2 Auth Test Data */
struct {
    uint32_t ChallengeFlags;
    uint8_t TargetInfo[36];
    struct ntlm_key ResponseKeyNT;
    struct ntlm_key SessionBaseKey;
    uint8_t LMv2Response[16];
    uint8_t NTLMv2Response[16];
    struct ntlm_key EncryptedSessionKey;
    uint8_t ChallengeMessage[0x68];
    /* Version field differs from the one MS DOCS generated */
    uint8_t EncChallengeMessage[0x68];
    uint8_t AuthenticateMessage[0xE8];
} T_NTLMv2 = {
    (
      NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH |
      NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_VERSION |
      NTLMSSP_NEGOTIATE_TARGET_INFO |
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
      NTLMSSP_TARGET_TYPE_SERVER |
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM |
      NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_SIGN |
      NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_UNICODE
    ),
    {
      /* MSV_AV_NB_DOMAIN_NAME, 12 "D.o.m.a.i.n." */
      0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00,
      0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
      /* MSV_AV_NB_COMPUTER_NAME, 12 "S.e.r.v.e.r." */
      0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00,
      0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
      /* MSV_AV_EOL, 0 */
      0x00, 0x00, 0x00, 0x00
    },
    {
      .data = {
        0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93,
        0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
      },
      .length = 16
    },
    {
      .data = {
        0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82,
        0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3
      },
      .length = 16
    },
    {
        0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10,
        0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19
    },
    {
        0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96,
        0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c
    },
    {
      .data = {
        0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90,
        0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e
      },
      .length = 16
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
        0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x02, 0x00, 0x0c, 0x00,
        0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00,
        0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00, 0x00,
        0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x02, 0x00, 0x0c, 0x00,
        0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00,
        0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
        0x6c, 0x00, 0x00, 0x00, 0x54, 0x00, 0x54, 0x00,
        0x84, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0xd8, 0x00, 0x00, 0x00, 0x35, 0x82, 0x88, 0xe2,
        0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f,
        0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x55, 0x00, 0x73, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f, 0x00,
        0x4d, 0x00, 0x50, 0x00, 0x55, 0x00, 0x54, 0x00,
        0x45, 0x00, 0x52, 0x00, 0x86, 0xc3, 0x50, 0x97,
        0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a,
        0x57, 0xcc, 0xcc, 0x19, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0x68, 0xcd, 0x0a, 0xb8,
        0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b,
        0xeb, 0xef, 0x6a, 0x1c, 0x01, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00,
        0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
        0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90,
        0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e
    }
};

int test_NTOWFv2(struct ntlm_ctx *ctx)
{
    struct ntlm_key nt_hash = { .length = 16 };
    struct ntlm_key result = { .length = 16 };
    int ret;

    ret = ntlm_pwd_to_nt_hash(T_Passwd, &nt_hash);
    if (ret) return ret;

    ret = NTOWFv2(ctx, &nt_hash, T_User, T_UserDom, &result);
    if (ret) return ret;

    if (memcmp(result.data, T_NTLMv2.ResponseKeyNT.data, 16) != 0) {
        fprintf(stderr, "results differ!\n");
        fprintf(stderr, "expected %s\n",
                        hex_to_str_16(T_NTLMv2.ResponseKeyNT.data));
        fprintf(stderr, "obtained %s\n",
                        hex_to_str_16(result.data));
        ret = EINVAL;
    }

    return ret;
}

int test_LMResponseV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer result;
    int ret;

    ret = ntlmv2_compute_lm_response(&T_NTLMv2.ResponseKeyNT,
                                     T_ServerChallenge, T_ClientChallenge,
                                     &result);
    if (ret) return ret;

    if (memcmp(result.data, T_NTLMv2.LMv2Response, 16) != 0) {
        fprintf(stderr, "results differ!\n");
        fprintf(stderr, "expected %s\n",
                        hex_to_str_16(T_NTLMv2.LMv2Response));
        fprintf(stderr, "obtained %s\n",
                        hex_to_str_16(result.data));
        ret = EINVAL;
    }

    free(result.data);
    return ret;
}

int test_NTResponseV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer target_info = { T_NTLMv2.TargetInfo, 36 };
    struct ntlm_buffer result;
    int ret;

    ret = ntlmv2_compute_nt_response(&T_NTLMv2.ResponseKeyNT,
                                     T_ServerChallenge, T_ClientChallenge,
                                     T_time, &target_info, &result);
    if (ret) return ret;

    if (memcmp(result.data, T_NTLMv2.NTLMv2Response, 16) != 0) {
        fprintf(stderr, "results differ!\n");
        fprintf(stderr, "expected %s\n",
                        hex_to_str_16(T_NTLMv2.NTLMv2Response));
        fprintf(stderr, "obtained %s\n",
                        hex_to_str_16(result.data));
        ret = EINVAL;
    }

    free(result.data);
    return ret;
}

int test_SessionBaseKeyV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer nt_response = { T_NTLMv2.NTLMv2Response, 16 };
    struct ntlm_key session_base_key = { .length = 16 };
    int ret;

    ret = ntlmv2_session_base_key(&T_NTLMv2.ResponseKeyNT,
                                  &nt_response, &session_base_key);
    if (ret) return ret;

    if (memcmp(session_base_key.data, T_NTLMv2.SessionBaseKey.data, 16) != 0) {
        fprintf(stderr, "results differ!\n");
        fprintf(stderr, "expected %s\n",
                        hex_to_str_16(T_NTLMv2.SessionBaseKey.data));
        fprintf(stderr, "obtained %s\n",
                        hex_to_str_16(session_base_key.data));
        ret = EINVAL;
    }

    return ret;
}

int test_EncryptedSessionKey(struct ntlm_ctx *ctx,
                             struct ntlm_key *key_exchange_key,
                             struct ntlm_key *encrypted_session_key)
{
    struct ntlm_key exported_session_key = { .length = 16 };
    struct ntlm_key encrypted_random_session_key = { .length = 16 };
    int ret;

    memcpy(exported_session_key.data, T_RandomSessionKey, 16);

    ret = ntlm_encrypted_session_key(key_exchange_key,
                                     &exported_session_key,
                                     &encrypted_random_session_key);
    if (ret) return ret;

    if (memcmp(encrypted_random_session_key.data,
               encrypted_session_key->data, 16) != 0) {
        fprintf(stderr, "results differ!\n");
        fprintf(stderr, "expected %s\n",
                        hex_to_str_16(encrypted_session_key->data));
        fprintf(stderr, "obtained %s\n",
                        hex_to_str_16(encrypted_random_session_key.data));
        ret = EINVAL;
    }

    return ret;
}

int test_DecodeChallengeMessageV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer chal_msg = { T_NTLMv2.ChallengeMessage, 0x68 };
    uint32_t type;
    uint32_t flags;
    char *target_name = NULL;
    uint8_t chal[8];
    struct ntlm_buffer challenge = { chal, 8 };
    struct ntlm_buffer target_info = { 0 };
    int ret;

    ret = ntlm_decode_msg_type(ctx, &chal_msg, &type);
    if (ret) return ret;
    if (type != 2) return EINVAL;

    ret = ntlm_decode_chal_msg(ctx, &chal_msg, &flags, &target_name,
                               &challenge, &target_info);
    if (ret) return ret;

    if (flags != T_NTLMv2.ChallengeFlags) {
        fprintf(stderr, "flags differ!\n");
        fprintf(stderr, "expected %d\n", T_NTLMv2.ChallengeFlags);
        fprintf(stderr, "obtained %d\n", flags);
        ret = EINVAL;
    }

    if (strcmp(target_name, T_Server_Name) != 0) {
        fprintf(stderr, "Target Names differ!\n");
        fprintf(stderr, "expected %s\n", T_Server_Name);
        fprintf(stderr, "obtained %s\n", target_name);
        ret = EINVAL;
    }

    if (memcmp(chal, T_ServerChallenge, 8) != 0) {
        fprintf(stderr, "Challenges differ!\n");
        fprintf(stderr, "expected %s\n", hex_to_str_8(T_ServerChallenge));
        fprintf(stderr, "obtained %s\n", hex_to_str_8(chal));
        ret = EINVAL;
    }

    if ((target_info.length != 36) ||
        (memcmp(target_info.data, T_NTLMv2.TargetInfo, 36) != 0)) {
        fprintf(stderr, "Target Infos differ!\n");
        fprintf(stderr, "expected:\n%s",
                        hex_to_dump(T_NTLMv2.TargetInfo, 36));
        fprintf(stderr, "obtained:\n%s",
                        hex_to_dump(target_info.data, target_info.length));
        ret = EINVAL;
    }

    free(target_name);
    free(target_info.data);
    return ret;
}

int test_EncodeChallengeMessageV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer challenge = { T_ServerChallenge, 8 };
    struct ntlm_buffer target_info = { T_NTLMv2.TargetInfo, 36 };
    struct ntlm_buffer message = { 0 };
    int ret;

    ret = ntlm_encode_chal_msg(ctx, T_NTLMv2.ChallengeFlags, T_Server_Name,
                               &challenge, &target_info, &message);
    if (ret) return ret;

    if ((message.length != 0x68) ||
        (memcmp(message.data, T_NTLMv2.EncChallengeMessage, 0x68) != 0)) {
        fprintf(stderr, "Challenge Messages differ!\n");
        fprintf(stderr, "expected:\n%s",
                        hex_to_dump(T_NTLMv2.EncChallengeMessage, 0x68));
        fprintf(stderr, "obtained:\n%s",
                        hex_to_dump(message.data, message.length));
        ret = EINVAL;
    }

    free(message.data);
    return ret;
}

int test_DecodeAuthenticateMessageV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer auth_msg = { T_NTLMv2.AuthenticateMessage, 0xE8 };
    uint32_t type;
    struct ntlm_buffer lm_chalresp = { 0 };
    struct ntlm_buffer nt_chalresp = { 0 };
    char *dom = NULL;
    char *usr = NULL;
    char *wks = NULL;
    struct ntlm_buffer enc_sess_key = { 0 };
    int ret;

    ret = ntlm_decode_msg_type(ctx, &auth_msg, &type);
    if (ret) return ret;
    if (type != 3) return EINVAL;

    ret = ntlm_decode_auth_msg(ctx, &auth_msg, T_NTLMv2.ChallengeFlags,
                               &lm_chalresp, &nt_chalresp,
                               &dom, &usr, &wks,
                               &enc_sess_key, NULL);
    if (ret) return ret;

    if ((lm_chalresp.length != 24) ||
        (memcmp(lm_chalresp.data, T_NTLMv2.LMv2Response, 16) != 0)) {

        fprintf(stderr, "LM Challenges differ!\n");
        fprintf(stderr, "expected:\n%s",
                        hex_to_dump(T_NTLMv2.LMv2Response, 16));
        fprintf(stderr, "obtained:\n%s",
                        hex_to_dump(lm_chalresp.data, lm_chalresp.length));
        ret = EINVAL;
    }

    if ((nt_chalresp.length != 84) ||
        (memcmp(nt_chalresp.data, T_NTLMv2.NTLMv2Response, 16) != 0)) {

        fprintf(stderr, "NT Challenges differ!\n");
        fprintf(stderr, "expected:\n%s",
                        hex_to_dump(T_NTLMv2.NTLMv2Response, 16));
        fprintf(stderr, "obtained:\n%s",
                        hex_to_dump(nt_chalresp.data, nt_chalresp.length));
        ret = EINVAL;
    }

    if (strcmp(dom, T_UserDom) != 0) {
        fprintf(stderr, "Domain Names differ!\n");
        fprintf(stderr, "expected %s\n", T_UserDom);
        fprintf(stderr, "obtained %s\n", dom);
        ret = EINVAL;
    }

    if (strcmp(usr, T_User) != 0) {
        fprintf(stderr, "User Names differ!\n");
        fprintf(stderr, "expected %s\n", T_User);
        fprintf(stderr, "obtained %s\n", usr);
        ret = EINVAL;
    }

    if (strcmp(wks, T_Workstation) != 0) {
        fprintf(stderr, "Workstation Names differ!\n");
        fprintf(stderr, "expected %s\n", T_Workstation);
        fprintf(stderr, "obtained %s\n", wks);
        ret = EINVAL;
    }

    if ((enc_sess_key.length != 16) ||
        (memcmp(enc_sess_key.data,
                T_NTLMv2.EncryptedSessionKey.data, 16) != 0)) {

        fprintf(stderr, "EncryptedSessionKey differ!\n");
        fprintf(stderr, "expected:\n%s",
                        hex_to_dump(T_NTLMv2.EncryptedSessionKey.data, 16));
        fprintf(stderr, "obtained:\n%s",
                        hex_to_dump(enc_sess_key.data, enc_sess_key.length));
        ret = EINVAL;
    }

    free(lm_chalresp.data);
    free(nt_chalresp.data);
    free(dom);
    free(usr);
    free(wks);
    free(enc_sess_key.data);
    return ret;
}

int test_EncodeAuthenticateMessageV2(struct ntlm_ctx *ctx)
{
    int ret = 0;






    return ret;
}

int main(int argc, const char *argv[])
{
    struct ntlm_ctx *ctx;
    int ret;

    ret = ntlm_init_ctx(&ctx);
    if (ret) goto done;

    fprintf(stdout, "Test NTOWFv2\n");
    ret = test_NTOWFv2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test LMResponse v2\n");
    ret = test_LMResponseV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test NTResponse v2\n");
    ret = test_NTResponseV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test SessionBaseKey v2\n");
    ret = test_SessionBaseKeyV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test EncryptedSessionKey v2\n");
    ret = test_EncryptedSessionKey(ctx, &T_NTLMv2.SessionBaseKey,
                                   &T_NTLMv2.EncryptedSessionKey);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test decoding ChallengeMessage v2\n");
    ret = test_DecodeChallengeMessageV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test encoding ChallengeMessage v2\n");
    ret = test_EncodeChallengeMessageV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test decoding AuthenticateMessage v2\n");
    ret = test_DecodeAuthenticateMessageV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

    fprintf(stdout, "Test encoding AuthenticateMessage v2\n");
    ret = test_EncodeAuthenticateMessageV2(ctx);
    fprintf(stdout, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));

done:
    ntlm_free_ctx(&ctx);
    return ret;
}
