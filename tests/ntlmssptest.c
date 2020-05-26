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
#include <stdlib.h>
#include <time.h>

#include "config.h"

#include "../src/gssapi_ntlmssp.h"
#include "../src/gss_ntlmssp.h"

const char *hex_to_dump(const uint8_t *d, size_t s)
{
    static char hex_to_dump_str[1536];
    char format[] = " %02x";
    size_t t, i, j, k, p;
    bool print_trail = false;
    bool next_line = false;

    if (s > 256) t = 256;
    else t = s;

    for (i = 0, p = 0; i < t; i++) {
        snprintf(&hex_to_dump_str[p], 4, format, d[i]);
        p += 3;
        k = (i + 1) % 16;
        if (i + 1 == t) {
            print_trail = true;
            next_line = false;
        } else if (k == 0) {
            print_trail = true;
            next_line = true;
        }
        if (print_trail) {
            for (j = 16 - k + 1; j > 0; j--) {
                hex_to_dump_str[p++] = ' ';
                hex_to_dump_str[p++] = ' ';
                hex_to_dump_str[p++] = ' ';
            }
            hex_to_dump_str[p++] = '|';
            if (k == 0) k = 16;
            for (j = 0; j < 16; j++) {
                if (k > 0) {
                    if (isalnum(d[j])) hex_to_dump_str[p++] = d[j];
                    else hex_to_dump_str[p++] = '.';
                    k--;
                } else hex_to_dump_str[p++] = ' ';
            }
            hex_to_dump_str[p++] = '|';
            print_trail = false;
        }
        if (next_line) {
            hex_to_dump_str[p++] = '\n';
            hex_to_dump_str[p] = '\0';
            next_line = false;
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

static int test_difference(const char *text,
                           const void *expected, size_t expected_len,
                           const void *obtained, size_t obtained_len)
{
    if (expected_len == 0) expected_len = strlen((const char *)expected);
    if (obtained_len == 0) obtained_len = strlen((const char *)obtained);
    if ((expected_len != obtained_len) ||
        (memcmp(expected, obtained, expected_len) != 0)) {
        fprintf(stderr, "%s differ!\n", text);
        fprintf(stderr, "expected\n%s", hex_to_dump(expected, expected_len));
        fprintf(stderr, "obtained\n%s", hex_to_dump(obtained, obtained_len));
        return EINVAL;
    }
    return 0;
}

static int test_buffers(const char *text,
                        struct ntlm_buffer *expected,
                        struct ntlm_buffer *obtained)
{
    return test_difference(text,
                           expected->data, expected->length,
                           obtained->data, obtained->length);
}

static int test_keys(const char *text,
                     struct ntlm_key *expected,
                     struct ntlm_key *obtained)
{
    return test_difference(text,
                           expected->data, expected->length,
                           obtained->data, obtained->length);
}

/* Test Data as per para 4.2 of MS-NLMP */
const char *T_User = "User";
const char *T_UserDom = "Domain";
const char *T_Passwd = "Password";
const char *T_Server_Name = "Server";
const char *T_Workstation = "COMPUTER";
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

/* NTLMv1 Auth Test Data */
struct {
    struct ntlm_key ResponseKeyLM;
    struct ntlm_key ResponseKeyNT;
    struct ntlm_key SessionBaseKey;
    uint8_t LMv1Response[24];
    uint8_t NTLMv1Response[24];
    struct ntlm_key KeyExchangeKey;
    struct ntlm_key EncryptedSessionKey1;
    struct ntlm_key EncryptedSessionKey2;
    struct ntlm_key EncryptedSessionKey3;
    uint32_t ChallengeFlags;
    uint8_t ChallengeMessage[0x44];
    uint8_t AuthenticateMessage[0xAC];
} T_NTLMv1 = {
    {
      .data = {
        0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22,
        0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6, 0xcb, 0x6d
      },
      .length = 16
    },
    {
      .data = {
        0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
        0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52
      },
      .length = 16
    },
    {
      .data = {
        0xd8, 0x72, 0x62, 0xb0, 0xcd, 0xe4, 0xb1, 0xcb,
        0x74, 0x99, 0xbe, 0xcc, 0xcd, 0xf1, 0x07, 0x84
      },
      .length = 16
    },
    {
        0x98, 0xde, 0xf7, 0xb8, 0x7f, 0x88, 0xaa, 0x5d,
        0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88, 0xa1, 0x72,
        0xde, 0xf1, 0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13
    },
    {
        0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2,
        0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16, 0x33, 0x1c,
        0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84, 0x1f, 0x94
    },
    {
      .data = {
        0xb0, 0x9e, 0x37, 0x9f, 0x7f, 0xbe, 0xcb, 0x1e,
        0xaf, 0x0a, 0xfd, 0xcb, 0x03, 0x83, 0xc8, 0xa0
      },
      .length = 16
    },
    {
      .data = {
        0x51, 0x88, 0x22, 0xb1, 0xb3, 0xf3, 0x50, 0xc8,
        0x95, 0x86, 0x82, 0xec, 0xbb, 0x3e, 0x3c, 0xb7
      },
      .length = 16
    },
    {
      .data = {
        0x74, 0x52, 0xca, 0x55, 0xc2, 0x25, 0xa1, 0xca,
        0x04, 0xb4, 0x8f, 0xae, 0x32, 0xcf, 0x56, 0xfc
      },
      .length = 16
    },
    {
      .data = {
        0x4c, 0xd7, 0xbb, 0x57, 0xd6, 0x97, 0xef, 0x9b,
        0x54, 0x9f, 0x02, 0xb8, 0xf9, 0xb3, 0x78, 0x64
      },
      .length = 16
    },
    (
      NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH |
      NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_VERSION |
      NTLMSSP_TARGET_TYPE_SERVER |
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM |
      NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_SIGN |
      NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_UNICODE
    ),
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x02, 0xe2,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
        0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x72, 0x00
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
        0x6c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
        0x84, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x9c, 0x00, 0x00, 0x00, 0x35, 0x82, 0x80, 0xe2,
        0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f,
        0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x55, 0x00, 0x73, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f, 0x00,
        0x4d, 0x00, 0x50, 0x00, 0x55, 0x00, 0x54, 0x00,
        0x45, 0x00, 0x52, 0x00, 0x98, 0xde, 0xf7, 0xb8,
        0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77,
        0x96, 0x88, 0xa1, 0x72, 0xde, 0xf1, 0x1c, 0x7d,
        0x5c, 0xcd, 0xef, 0x13, 0x67, 0xc4, 0x30, 0x11,
        0xf3, 0x02, 0x98, 0xa2, 0xad, 0x35, 0xec, 0xe6,
        0x4f, 0x16, 0x33, 0x1c, 0x44, 0xbd, 0xbe, 0xd9,
        0x27, 0x84, 0x1f, 0x94, 0x51, 0x88, 0x22, 0xb1,
        0xb3, 0xf3, 0x50, 0xc8, 0x95, 0x86, 0x82, 0xec,
        0xbb, 0x3e, 0x3c, 0xb7
    }
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

/* NTLMv2 Auth with Channel Bindings Test Data */
struct {
    uint32_t ChallengeFlags;
    const char *User;
    const char *Password;
    const char *Domain;
    const char *Workstation;
    const char *Server;
    const char *DnsDomain;
    const char *DnsServer;
    const char *Forest;
    uint64_t ServerTime;
    uint8_t ServerChallenge[8];
    struct ntlm_key NTLMHash;
    uint8_t TargetInfo[0xb6];
    uint8_t ChallengeMessage[0xfe];
    uint8_t AuthenticateMessage[0x228];
    uint8_t MIC[16];
    uint8_t CBSum[16];
} T_NTLMv2_CBT = {
    (
      NTLMSSP_NEGOTIATE_56 |
      NTLMSSP_NEGOTIATE_128 |
      NTLMSSP_NEGOTIATE_VERSION |
      NTLMSSP_NEGOTIATE_TARGET_INFO |
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
      NTLMSSP_TARGET_TYPE_DOMAIN |
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
      NTLMSSP_NEGOTIATE_NTLM |
      NTLMSSP_REQUEST_TARGET |
      NTLMSSP_NEGOTIATE_UNICODE
    ),
    "Administrator",
    "P@ssw0rd",
    "WS2008R2",
    "WIN7-2-PC",
    "DC-WS2008R2",
    "ws2008r2.local",
    "DC-ws2008r2.ws2008r2.local",
    "ws2008r2.local",
    0x01cdde0bc33fe77b,
    { 0xa2, 0xc5, 0xe8, 0xca, 0x30, 0x84, 0xaa, 0x72 },
    {
      .data = {
        0xe1, 0x9c, 0xcf, 0x75, 0xee, 0x54, 0xe0, 0x6b,
        0x06, 0xa5, 0x90, 0x7a, 0xf1, 0x3c, 0xef, 0x42
      },
      .length = 16
    },
    {
        0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x53, 0x00,
        0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x38, 0x00,
        0x52, 0x00, 0x32, 0x00, 0x01, 0x00, 0x16, 0x00,
        0x44, 0x00, 0x43, 0x00, 0x2d, 0x00, 0x57, 0x00,
        0x53, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x04, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x03, 0x00,
        0x34, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2d, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x72, 0x00, 0x32, 0x00,
        0x2e, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x05, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x07, 0x00,
        0x08, 0x00, 0x7b, 0xe7, 0x3f, 0xc3, 0x0b, 0xde,
        0xcd, 0x01, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x05, 0x82, 0x89, 0xa2,
        0xa2, 0xc5, 0xe8, 0xca, 0x30, 0x84, 0xaa, 0x72,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb6, 0x00, 0xb6, 0x00, 0x48, 0x00, 0x00, 0x00,
        0x06, 0x01, 0xb0, 0x1d, 0x00, 0x00, 0x00, 0x0f,
        0x57, 0x00, 0x53, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00,
        0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x53, 0x00,
        0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x38, 0x00,
        0x52, 0x00, 0x32, 0x00, 0x01, 0x00, 0x16, 0x00,
        0x44, 0x00, 0x43, 0x00, 0x2d, 0x00, 0x57, 0x00,
        0x53, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x04, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x03, 0x00,
        0x34, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2d, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x72, 0x00, 0x32, 0x00,
        0x2e, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x05, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x07, 0x00,
        0x08, 0x00, 0x7b, 0xe7, 0x3f, 0xc3, 0x0b, 0xde,
        0xcd, 0x01, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
        0x94, 0x00, 0x00, 0x00, 0x7c, 0x01, 0x7c, 0x01,
        0xac, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x58, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x1a, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x12, 0x00, 0x12, 0x00,
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x02, 0x00, 0x00, 0x05, 0x82, 0x88, 0xa2,
        0x06, 0x01, 0xb0, 0x1d, 0x00, 0x00, 0x00, 0x0f,
        0xf0, 0x54, 0xa5, 0x42, 0xb0, 0x90, 0xb6, 0x6c,
        0x1f, 0xea, 0x1a, 0x2c, 0xc8, 0x2e, 0x93, 0x0b,
        0x57, 0x00, 0x53, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00,
        0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
        0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00,
        0x72, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00,
        0x37, 0x00, 0x2d, 0x00, 0x32, 0x00, 0x2d, 0x00,
        0x50, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5a, 0x6a, 0x21, 0xae,
        0x1a, 0x44, 0xc0, 0x44, 0x69, 0x3e, 0xee, 0x59,
        0xfc, 0x5d, 0x81, 0xe0, 0x01, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x7b, 0xe7, 0x3f, 0xc3,
        0x0b, 0xde, 0xcd, 0x01, 0x27, 0xfc, 0x11, 0x80,
        0x82, 0xc2, 0xfb, 0xdd, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x53, 0x00,
        0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x38, 0x00,
        0x52, 0x00, 0x32, 0x00, 0x01, 0x00, 0x16, 0x00,
        0x44, 0x00, 0x43, 0x00, 0x2d, 0x00, 0x57, 0x00,
        0x53, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x04, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x03, 0x00,
        0x34, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2d, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x72, 0x00, 0x32, 0x00,
        0x2e, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x05, 0x00,
        0x1c, 0x00, 0x77, 0x00, 0x73, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x38, 0x00, 0x72, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00,
        0x63, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x07, 0x00,
        0x08, 0x00, 0x7b, 0xe7, 0x3f, 0xc3, 0x0b, 0xde,
        0xcd, 0x01, 0x06, 0x00, 0x04, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x4d, 0x6b,
        0x0d, 0x27, 0x54, 0x10, 0x22, 0xf5, 0xff, 0xa6,
        0x73, 0xda, 0x2b, 0xfc, 0xfd, 0xf1, 0x94, 0x2f,
        0x25, 0x7b, 0xe1, 0x1a, 0x49, 0xc9, 0x54, 0x19,
        0x7a, 0xca, 0x8a, 0xaf, 0x2e, 0xaf, 0x0a, 0x00,
        0x10, 0x00, 0x65, 0x86, 0xe9, 0x9d, 0x81, 0xc2,
        0xfc, 0x98, 0x4e, 0x47, 0x17, 0x2f, 0xd4, 0xdd,
        0x03, 0x10, 0x09, 0x00, 0x3e, 0x00, 0x48, 0x00,
        0x54, 0x00, 0x54, 0x00, 0x50, 0x00, 0x2f, 0x00,
        0x64, 0x00, 0x63, 0x00, 0x2d, 0x00, 0x77, 0x00,
        0x73, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x38, 0x00, 0x72, 0x00, 0x32, 0x00, 0x2e, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x32, 0x00, 0x30, 0x00,
        0x30, 0x00, 0x38, 0x00, 0x72, 0x00, 0x32, 0x00,
        0x2e, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x63, 0x00,
        0x61, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0xf0, 0x54, 0xa5, 0x42, 0xb0, 0x90, 0xb6, 0x6c,
        0x1f, 0xea, 0x1a, 0x2c, 0xc8, 0x2e, 0x93, 0x0b
    },
    {
        0x65, 0x86, 0xE9, 0x9D, 0x81, 0xC2, 0xFC, 0x98,
        0x4E, 0x47, 0x17, 0x2F, 0xD4, 0xDD, 0x03, 0x10
    },
};

struct t_gsswrapex_data {
    uint32_t flags;
    struct ntlm_buffer Plaintext;
    struct ntlm_key KeyExchangeKey;
    struct ntlm_key ClientSealKey;
    struct ntlm_key ClientSignKey;
    struct ntlm_buffer Ciphertext;
    struct ntlm_buffer Signature;
};

/* Basic GSS_WrapEx V1 Test Data */

uint8_t T_GSSWRAPv1noESS_Plaintext_data[18] = {
    0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
    0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00
};
uint8_t T_GSSWRAPv1noESS_Ciphertext_data[18] = {
    0x56, 0xfe, 0x04, 0xd8, 0x61, 0xf9, 0x31, 0x9a, 0xf0,
    0xd7, 0x23, 0x8a, 0x2e, 0x3b, 0x4d, 0x45, 0x7f, 0xb8
};
uint8_t T_GSSWRAPv1noESS_Signature_data[16] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 0xdc, 0xd1, 0xdf, 0x2e, 0x45, 0x9d, 0x36
};

struct t_gsswrapex_data T_GSSWRAPv1noESS = {
    (
      NTLMSSP_NEGOTIATE_56 |
      NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL
    ),
    {
      .data = T_GSSWRAPv1noESS_Plaintext_data,
      .length = sizeof(T_GSSWRAPv1noESS_Plaintext_data)
    },
    {
      .data = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
      },
      .length = 16
    },
    {
      .data = { 0 },
      .length = 0
    },
    {
      .data = { 0 },
      .length = 0
    },
    {
      .data = T_GSSWRAPv1noESS_Ciphertext_data,
      .length = sizeof(T_GSSWRAPv1noESS_Ciphertext_data)
    },
    {
      .data = T_GSSWRAPv1noESS_Signature_data,
      .length = sizeof(T_GSSWRAPv1noESS_Signature_data)
    },
};

/* GSS_WrapEx V1 Extended Session Security Test Data */

uint8_t T_GSSWRAPEXv1_Plaintext_data[18] = {
    0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
    0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00
};
uint8_t T_GSSWRAPEXv1_Ciphertext_data[18] = {
    0xa0, 0x23, 0x72, 0xf6, 0x53, 0x02, 0x73, 0xf3, 0xaa,
    0x1e, 0xb9, 0x01, 0x90, 0xce, 0x52, 0x00, 0xc9, 0x9d
};
uint8_t T_GSSWRAPEXv1_Signature_data[16] = {
    0x01, 0x00, 0x00, 0x00, 0xff, 0x2a, 0xeb, 0x52,
    0xf6, 0x81, 0x79, 0x3a, 0x00, 0x00, 0x00, 0x00
};

struct t_gsswrapex_data T_GSSWRAPEXv1 = {
    (
      NTLMSSP_NEGOTIATE_56 |
      NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL |
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    ),
    {
      .data = T_GSSWRAPEXv1_Plaintext_data,
      .length = sizeof(T_GSSWRAPEXv1_Plaintext_data)
    },
    {
      .data = {
        0xeb, 0x93, 0x42, 0x9a, 0x8b, 0xd9, 0x52, 0xf8,
        0xb8, 0x9c, 0x55, 0xb8, 0x7f, 0x47, 0x5e, 0xdc
      },
      .length = 16
    },
    {
      .data = {
        0x04, 0xdd, 0x7f, 0x01, 0x4d, 0x85, 0x04, 0xd2,
        0x65, 0xa2, 0x5c, 0xc8, 0x6a, 0x3a, 0x7c, 0x06
      },
      .length = 16
    },
    {
      .data = {
        0x60, 0xe7, 0x99, 0xbe, 0x5c, 0x72, 0xfc, 0x92,
        0x92, 0x2a, 0xe8, 0xeb, 0xe9, 0x61, 0xfb, 0x8d
      },
      .length = 16
    },
    {
      .data = T_GSSWRAPEXv1_Ciphertext_data,
      .length = sizeof(T_GSSWRAPEXv1_Ciphertext_data)
    },
    {
      .data = T_GSSWRAPEXv1_Signature_data,
      .length = sizeof(T_GSSWRAPEXv1_Signature_data)
    },
};

/* GSS_WrapEx V2 Test Data */

uint8_t T_GSSWRAPEXv2_Plaintext_data[18] = {
    0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
    0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00
};
uint8_t T_GSSWRAPEXv2_Ciphertext_data[18] = {
    0x54, 0xe5, 0x01, 0x65, 0xbf, 0x19, 0x36, 0xdc, 0x99,
    0x60, 0x20, 0xc1, 0x81, 0x1b, 0x0f, 0x06, 0xfb, 0x5f
};
uint8_t T_GSSWRAPEXv2_Signature_data[16] = {
    0x01, 0x00, 0x00, 0x00, 0x7f, 0xb3, 0x8e, 0xc5,
    0xc5, 0x5d, 0x49, 0x76, 0x00, 0x00, 0x00, 0x00
};

struct t_gsswrapex_data T_GSSWRAPEXv2 = {
    (
      NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_128 |
      NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL |
      NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    ),
    {
      .data = T_GSSWRAPEXv2_Plaintext_data,
      .length = sizeof(T_GSSWRAPEXv2_Plaintext_data)
    },
    {
      .data = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
    },
      .length = 16
    },
    {
      .data = {
        0x59, 0xf6, 0x00, 0x97, 0x3c, 0xc4, 0x96, 0x0a,
        0x25, 0x48, 0x0a, 0x7c, 0x19, 0x6e, 0x4c, 0x58
      },
      .length = 16
    },
    {
      .data = {
        0x47, 0x88, 0xdc, 0x86, 0x1b, 0x47, 0x82, 0xf3,
        0x5d, 0x43, 0xfd, 0x98, 0xfe, 0x1a, 0x2d, 0x39
      },
      .length = 16
    },
    {
      .data = T_GSSWRAPEXv2_Ciphertext_data,
      .length = sizeof(T_GSSWRAPEXv2_Ciphertext_data)
    },
    {
      .data = T_GSSWRAPEXv2_Signature_data,
      .length = sizeof(T_GSSWRAPEXv2_Signature_data)
    },
};

int test_LMOWFv1(struct ntlm_ctx *ctx)
{
    struct ntlm_key result = { .length = 16 };
    int ret;

    ret = LMOWFv1(T_Passwd, &result);
    if (ret) return ret;

    return test_keys("results", &T_NTLMv1.ResponseKeyLM, &result);
}

int test_NTOWFv1(struct ntlm_ctx *ctx)
{
    struct ntlm_key result = { .length = 16 };
    int ret;

    ret = NTOWFv1(T_Passwd, &result);
    if (ret) return ret;

    return test_keys("results", &T_NTLMv1.ResponseKeyNT, &result);
}

int test_SessionBaseKeyV1(struct ntlm_ctx *ctx)
{
    struct ntlm_key session_base_key = { .length = 16 };
    int ret;

    ret = ntlm_session_base_key(&T_NTLMv1.ResponseKeyNT, &session_base_key);
    if (ret) return ret;

    return test_keys("results",
                        &T_NTLMv1.SessionBaseKey, &session_base_key);
}

int test_LMResponseV1(struct ntlm_ctx *ctx)
{
    uint8_t buf[24];
    struct ntlm_buffer result = { buf, 24 };
    int ret;

    ret = ntlm_compute_lm_response(&T_NTLMv1.ResponseKeyLM, false,
                                   T_ServerChallenge, T_ClientChallenge,
                                   &result);
    if (ret) return ret;

    return test_difference("results",
                           T_NTLMv1.LMv1Response,
                           sizeof(T_NTLMv1.LMv1Response),
                           result.data, result.length);
}

int test_NTResponseV1(struct ntlm_ctx *ctx)
{
    uint8_t buf[24];
    struct ntlm_buffer result = { buf, 24 };
    int ret;

    ret = ntlm_compute_nt_response(&T_NTLMv1.ResponseKeyNT, false,
                                   T_ServerChallenge, T_ClientChallenge,
                                   &result);
    if (ret) return ret;

    return test_difference("results",
                           T_NTLMv1.NTLMv1Response,
                           sizeof(T_NTLMv1.NTLMv1Response),
                           result.data, result.length);
}

int test_LM_KeyExchangeKey(struct ntlm_ctx *ctx)
{
    struct ntlm_key result = { .length = 16 };
    struct ntlm_buffer lm_response = {
        .data = T_NTLMv1.LMv1Response,
        .length = sizeof(T_NTLMv1.LMv1Response)
    };
    int ret;

    ret = KXKEY(ctx, false, true, false, T_ServerChallenge,
                &T_NTLMv1.ResponseKeyLM, &T_NTLMv1.SessionBaseKey,
                &lm_response, &result);
    if (ret) return ret;

    return test_keys("results", &T_NTLMv1.KeyExchangeKey, &result);
}

int test_NTOWFv2(struct ntlm_ctx *ctx)
{
    struct ntlm_key nt_hash = { .length = 16 };
    struct ntlm_key result = { .length = 16 };
    int ret;

    ret = NTOWFv1(T_Passwd, &nt_hash);
    if (ret) return ret;

    ret = NTOWFv2(ctx, &nt_hash, T_User, T_UserDom, &result);
    if (ret) return ret;

    return test_keys("results", &T_NTLMv2.ResponseKeyNT, &result);
}

int test_LMResponseV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer result;
    int ret;

    ret = ntlmv2_compute_lm_response(&T_NTLMv2.ResponseKeyNT,
                                     T_ServerChallenge, T_ClientChallenge,
                                     &result);
    if (ret) return ret;

    ret = test_difference("results",
                          T_NTLMv2.LMv2Response,
                          sizeof(T_NTLMv2.LMv2Response),
                          result.data,
                          sizeof(T_NTLMv2.LMv2Response));

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

    ret = test_difference("results",
                          T_NTLMv2.NTLMv2Response,
                          sizeof(T_NTLMv2.NTLMv2Response),
                          result.data,
                          sizeof(T_NTLMv2.NTLMv2Response));

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

    return test_keys("results", &T_NTLMv2.SessionBaseKey, &session_base_key);
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

    return test_keys("results", encrypted_session_key,
                                &encrypted_random_session_key);
}

int test_EncryptedSessionKey1(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer lm_response = { T_NTLMv1.LMv1Response, 24 };
    struct ntlm_key key_exchnage_key = { .length = 16 };
    int ret;

    ret = KXKEY(ctx, false, false, false, T_ServerChallenge,
                &T_NTLMv1.ResponseKeyLM, &T_NTLMv1.SessionBaseKey,
                &lm_response, &key_exchnage_key);
    if (ret) return ret;

    return test_EncryptedSessionKey(ctx, &key_exchnage_key,
                                    &T_NTLMv1.EncryptedSessionKey1);
}

int test_EncryptedSessionKey2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer lm_response = { T_NTLMv1.LMv1Response, 24 };
    struct ntlm_key key_exchnage_key = { .length = 16 };
    int ret;

    ret = KXKEY(ctx, false, false, true, T_ServerChallenge,
                &T_NTLMv1.ResponseKeyLM, &T_NTLMv1.SessionBaseKey,
                &lm_response, &key_exchnage_key);
    if (ret) return ret;

    return test_EncryptedSessionKey(ctx, &key_exchnage_key,
                                    &T_NTLMv1.EncryptedSessionKey2);
}

int test_EncryptedSessionKey3(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer lm_response = { T_NTLMv1.LMv1Response, 24 };
    struct ntlm_key key_exchnage_key = { .length = 16 };
    int ret;

    ret = KXKEY(ctx, false, true, false, T_ServerChallenge,
                &T_NTLMv1.ResponseKeyLM, &T_NTLMv1.SessionBaseKey,
                &lm_response, &key_exchnage_key);
    if (ret) return ret;

    return test_EncryptedSessionKey(ctx, &key_exchnage_key,
                                    &T_NTLMv1.EncryptedSessionKey3);
}

int test_DecodeChallengeMessageV1(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer chal_msg = { T_NTLMv1.ChallengeMessage, 0x68 };
    uint32_t type;
    uint32_t flags;
    char *target_name = NULL;
    uint8_t chal[8];
    struct ntlm_buffer challenge = { chal, 8 };
    int err;
    int ret;

    ret = ntlm_decode_msg_type(ctx, &chal_msg, &type);
    if (ret) return ret;
    if (type != 2) return EINVAL;

    ret = ntlm_decode_chal_msg(ctx, &chal_msg, &flags, &target_name,
                               &challenge, NULL);
    if (ret) return ret;

    err = test_difference("flags", &T_NTLMv1.ChallengeFlags, 4, &flags, 4);
    if (err) ret = err;

    err = test_difference("Target Names", T_Server_Name, 0, target_name, 0);
    if (err) ret = err;

    err = test_difference("Challenges", T_ServerChallenge, 8, chal, 8);
    if (err) ret = err;

    free(target_name);
    return ret;
}

int test_EncodeChallengeMessageV1(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer challenge = { T_ServerChallenge, 8 };
    struct ntlm_buffer message = { 0 };
    int ret;

    ret = ntlm_encode_chal_msg(ctx, T_NTLMv1.ChallengeFlags, T_Server_Name,
                               &challenge, NULL, &message);
    if (ret) return ret;

    ret = test_difference("Challenge Messages",
                          T_NTLMv1.ChallengeMessage,
                          sizeof(T_NTLMv1.ChallengeMessage),
                          message.data, message.length);
    free(message.data);
    return ret;
}

int test_DecodeChallengeMessageV2(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer chal_msg = { T_NTLMv2.ChallengeMessage,
                                    sizeof(T_NTLMv2.ChallengeMessage) };
    uint32_t type;
    uint32_t flags;
    char *target_name = NULL;
    uint8_t chal[8];
    struct ntlm_buffer challenge = { chal, 8 };
    struct ntlm_buffer target_info = { 0 };
    int err;
    int ret;

    ret = ntlm_decode_msg_type(ctx, &chal_msg, &type);
    if (ret) return ret;
    if (type != 2) return EINVAL;

    ret = ntlm_decode_chal_msg(ctx, &chal_msg, &flags, &target_name,
                               &challenge, &target_info);
    if (ret) return ret;

    err = test_difference("flags", &T_NTLMv2.ChallengeFlags, 4, &flags, 4);
    if (err) ret = err;

    err = test_difference("Target Names", T_Server_Name, 0, target_name, 0);
    if (err) ret = err;

    err = test_difference("Challenges", T_ServerChallenge, 8, chal, 8);
    if (err) ret = err;

    err = test_difference("Target Infos",
                          T_NTLMv2.TargetInfo, 36,
                          target_info.data, target_info.length);
    if (err) ret = err;

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

    ret = test_difference("Challenge Messages",
                          T_NTLMv2.ChallengeMessage,
                          sizeof(T_NTLMv2.ChallengeMessage),
                          message.data, message.length);
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
    int err;
    int ret;

    ret = ntlm_decode_msg_type(ctx, &auth_msg, &type);
    if (ret) return ret;
    if (type != 3) return EINVAL;

    ret = ntlm_decode_auth_msg(ctx, &auth_msg, T_NTLMv2.ChallengeFlags,
                               &lm_chalresp, &nt_chalresp,
                               &dom, &usr, &wks,
                               &enc_sess_key, NULL, NULL);
    if (ret) return ret;

    if (lm_chalresp.length != 24) {
        fprintf(stderr, "Expected a 24 bytes long LM Challenge\n");
        fprintf(stderr, "Obtained %s",
                        hex_to_dump(lm_chalresp.data, lm_chalresp.length));
        ret = EINVAL;
    } else {
        err = test_difference("LM Challenges",
                              T_NTLMv2.LMv2Response,
                              sizeof(T_NTLMv2.LMv2Response),
                              lm_chalresp.data,
                              sizeof(T_NTLMv2.LMv2Response));
        if (err) ret = err;
    }

    if (nt_chalresp.length != 84) {
        fprintf(stderr, "Expected a 84 bytes long NT Challenge\n");
        fprintf(stderr, "Obtained %s",
                        hex_to_dump(nt_chalresp.data, nt_chalresp.length));
        ret = EINVAL;
    } else {
        err = test_difference("NT Challenges",
                              T_NTLMv2.NTLMv2Response,
                              sizeof(T_NTLMv2.LMv2Response),
                              nt_chalresp.data,
                              sizeof(T_NTLMv2.LMv2Response));
        if (err) ret = err;
    }

    err = test_difference("Domain Names", T_UserDom, 0, dom, 0);
    if (err) ret = err;

    err = test_difference("User Names", T_User, 0, usr, 0);
    if (err) ret = err;

    err = test_difference("Workstation Names", T_Workstation, 0, wks, 0);
    if (err) ret = err;

    err = test_difference("EncryptedSessionKey",
                          T_NTLMv2.EncryptedSessionKey.data,
                          T_NTLMv2.EncryptedSessionKey.length,
                          enc_sess_key.data,
                          enc_sess_key.length);
    if (err) ret = err;

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

int test_DecodeChallengeMessageV2CBT(struct ntlm_ctx *ctx)

{
    struct ntlm_buffer chal_msg = { T_NTLMv2_CBT.ChallengeMessage,
                                    sizeof(T_NTLMv2_CBT.ChallengeMessage) };
    uint32_t type;
    uint32_t flags;
    char *target_name = NULL;
    uint8_t chal[8];
    struct ntlm_buffer challenge = { chal, 8 };
    struct ntlm_buffer target_info = { 0 };
    int err;
    int ret;

    ret = ntlm_decode_msg_type(ctx, &chal_msg, &type);
    if (ret) return ret;
    if (type != 2) return EINVAL;

    ret = ntlm_decode_chal_msg(ctx, &chal_msg, &flags, &target_name,
                               &challenge, &target_info);
    if (ret) return ret;

    err = test_difference("flags",
                          &T_NTLMv2_CBT.ChallengeFlags, 4,
                          &flags, 4);
    if (err) ret = err;

    err = test_difference("Target Names",
                          T_NTLMv2_CBT.Domain, 0, target_name, 0);
    if (err) ret = err;

    err = test_difference("Challenges",
                          T_NTLMv2_CBT.ServerChallenge,
                          sizeof(T_NTLMv2_CBT.ServerChallenge),
                          chal, 8);
    if (err) ret = err;

    err = test_difference("Target Infos",
                          T_NTLMv2_CBT.TargetInfo,
                          sizeof(T_NTLMv2_CBT.TargetInfo),
                          target_info.data, target_info.length);
    if (err) ret = err;

    free(target_name);
    free(target_info.data);
    return ret;
}

int test_EncodeChallengeMessageV2CBT(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer challenge = { T_NTLMv2_CBT.ServerChallenge, 8 };
    struct ntlm_buffer target_info = { T_NTLMv2_CBT.TargetInfo,
                                       sizeof(T_NTLMv2_CBT.TargetInfo) };
    struct ntlm_buffer message = { 0 };
    int ret;

    ret = ntlm_encode_chal_msg(ctx, T_NTLMv2_CBT.ChallengeFlags,
                               T_NTLMv2_CBT.Domain, &challenge,
                               &target_info, &message);
    if (ret) return ret;

    ret = test_difference("Challenge Messages",
                          T_NTLMv2_CBT.ChallengeMessage,
                          sizeof(T_NTLMv2_CBT.ChallengeMessage),
                          message.data, message.length);
    free(message.data);
    return ret;
}

int test_DecodeAuthenticateMessageV2CBT(struct ntlm_ctx *ctx)
{
    struct ntlm_buffer auth_msg = { T_NTLMv2_CBT.AuthenticateMessage,
                                    sizeof(T_NTLMv2_CBT.AuthenticateMessage) };
    uint32_t type;
    struct ntlm_buffer lm_chalresp = { 0 };
    struct ntlm_buffer nt_chalresp = { 0 };
    char *dom = NULL;
    char *usr = NULL;
    char *wks = NULL;
    struct ntlm_buffer enc_sess_key = { 0 };
    uint8_t micdata[16];
    struct ntlm_buffer mic = { micdata, 16 };
    struct ntlm_key ntlmv2_key = { .length = 16 };
    struct ntlm_buffer target_info = { 0 };
    struct ntlm_buffer cb = { 0 };
    int ret, c;
    int err;

    ret = ntlm_decode_msg_type(ctx, &auth_msg, &type);
    if (ret) return ret;
    if (type != 3) return EINVAL;

    ret = ntlm_decode_auth_msg(ctx, &auth_msg, T_NTLMv2_CBT.ChallengeFlags,
                               &lm_chalresp, &nt_chalresp,
                               &dom, &usr, &wks,
                               &enc_sess_key, &target_info, &mic);
    if (ret) return ret;

    for (c = 1; lm_chalresp.length > c; c++) {
        lm_chalresp.data[0] |= lm_chalresp.data[c];
    }
    if ((lm_chalresp.length != 24) || (lm_chalresp.data[0] != 0)) {
        fprintf(stderr, "LM Challenge too short[%zd] or not all zeros!\n",
                        lm_chalresp.length);
        ret = EINVAL;
    }

    err = test_difference("Domain Names", T_NTLMv2_CBT.Domain, 0, dom, 0);
    if (err) ret = err;

    err = test_difference("User Names", T_NTLMv2_CBT.User, 0, usr, 0);
    if (err) ret = err;

    err = test_difference("Workstation Names",
                          T_NTLMv2_CBT.Workstation, 0, wks, 0);
    if (err) ret = err;

    if (enc_sess_key.length != 0) {
        fprintf(stderr, "Encrypted Random Session Key not null (%zd)!\n",
                        enc_sess_key.length);
        ret = EINVAL;
    }

    err = test_difference("MIC",
                          T_NTLMv2_CBT.MIC, sizeof(T_NTLMv2_CBT.MIC),
                          mic.data, mic.length);
    if (err) ret = err;

    ret = NTOWFv2(ctx, &T_NTLMv2_CBT.NTLMHash,
                  T_NTLMv2_CBT.User, T_NTLMv2_CBT.Domain,
                  &ntlmv2_key);
    if (ret) {
        fprintf(stderr, "NTLMv2 key generation failed!\n");
        goto done;
    }

    ret = ntlmv2_verify_nt_response(&nt_chalresp, &ntlmv2_key,
                                    T_NTLMv2_CBT.ServerChallenge);
    if (ret) {
        fprintf(stderr, "NTLMv2 Verification failed!\n");
        goto done;
    }

    ret = ntlm_decode_target_info(ctx, &target_info,
                                  NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL,
                                  NULL, &cb);
    if (ret) {
        fprintf(stderr, "NTLMv2 failed to decode target info!\n");
        goto done;
    }

    err = test_difference("CBTs",
                          T_NTLMv2_CBT.CBSum, sizeof(T_NTLMv2_CBT.CBSum),
                          cb.data, cb.length);
    if (err) ret = err;

done:
    free(lm_chalresp.data);
    free(nt_chalresp.data);
    free(dom);
    free(usr);
    free(wks);
    free(enc_sess_key.data);
    free(target_info.data);
    return ret;
}


int test_GSS_Wrap_EX(struct ntlm_ctx *ctx, struct t_gsswrapex_data *data)
{
    struct ntlm_signseal_state state;
    uint8_t outbuf[data->Ciphertext.length];
    uint8_t signbuf[16];
    struct ntlm_buffer output = { outbuf, data->Ciphertext.length };
    struct ntlm_buffer signature = { signbuf, 16 };
    int ret;
    int err;

    ret = ntlm_signseal_keys(data->flags, true,
                             &data->KeyExchangeKey, &state);
    if (ret) return ret;

    if (data->ClientSealKey.length) {
        err = test_keys("Client Sealing Keys",
                        &data->ClientSealKey, &state.send.seal_key);
        if (err) ret = err;
    }

    if (data->ClientSignKey.length) {
        err = test_keys("Client Signing Keys",
                        &data->ClientSignKey, &state.send.sign_key);
        if (err) ret = err;
    }

    if (ret) return ret;

    ret = ntlm_seal(data->flags, &state,
                    &data->Plaintext, &output, &signature);

    if (ret) {
        fprintf(stderr, "Sealing failed\n");
        return ret;
    }

    err = test_buffers("Ciphertext", &data->Ciphertext, &output);
    if (err) ret = err;

    err = test_buffers("Signature", &data->Signature, &signature);
    if (err) ret = err;

    return ret;
}

#define TEST_USER_FILE "examples/test_user_file.txt"

long seed = 0;
static size_t repeatable_rand(uint8_t *buf, size_t max)
{
    char *env_seed;
    size_t len;
    int i;

    if (seed == 0) {
        env_seed = getenv("NTLMSSPTEST_SEED");
        if (env_seed) {
            seed = strtol(env_seed, NULL, 0);
        } else {
            seed = time(NULL);
            fprintf(stdout, "repeatable_rand seed = %ld\n", seed);
        }
        srandom(seed);
    }

    len = random() % max;
    if (len < 5) len = 5;

    for (i = 0; i < len; i++) {
        buf[i] = random();
    }

    return len;
}

#define CASE(X) case X: return #X

const char *gss_maj_to_str(uint32_t err)
{
    switch (err) {
    CASE(GSS_S_COMPLETE);
    /* caling errors */
    CASE(GSS_S_CALL_INACCESSIBLE_READ);
    CASE(GSS_S_CALL_INACCESSIBLE_WRITE);
    CASE(GSS_S_CALL_BAD_STRUCTURE);
    /* routine errors */
    CASE(GSS_S_BAD_MECH);
    CASE(GSS_S_BAD_NAME);
    CASE(GSS_S_BAD_NAMETYPE);
    CASE(GSS_S_BAD_BINDINGS);
    CASE(GSS_S_BAD_STATUS);
    CASE(GSS_S_BAD_SIG);
    CASE(GSS_S_NO_CRED);
    CASE(GSS_S_NO_CONTEXT);
    CASE(GSS_S_DEFECTIVE_TOKEN);
    CASE(GSS_S_CREDENTIALS_EXPIRED);
    CASE(GSS_S_CONTEXT_EXPIRED);
    CASE(GSS_S_BAD_QOP);
    CASE(GSS_S_UNAUTHORIZED);
    CASE(GSS_S_UNAVAILABLE);
    CASE(GSS_S_DUPLICATE_ELEMENT);
    CASE(GSS_S_NAME_NOT_MN);
    CASE(GSS_S_BAD_MECH_ATTR);
    /* supplementary info */
    CASE(GSS_S_CONTINUE_NEEDED);
    CASE(GSS_S_DUPLICATE_TOKEN);
    CASE(GSS_S_OLD_TOKEN);
    CASE(GSS_S_UNSEQ_TOKEN);
    CASE(GSS_S_GAP_TOKEN);
    default:
        return "Unknown Error";
    }
}

static void print_min_status(uint32_t err)
{
    gss_buffer_desc buf;
    uint32_t msgctx = 0;
    uint32_t retmaj;
    uint32_t retmin;

    do {
        retmaj = gssntlm_display_status(&retmin, err, GSS_C_MECH_CODE,
                                        NULL, &msgctx, &buf);
        if (retmaj) {
            fprintf(stderr, "!!gssntlm_display_status failed for err=%d", err);
            msgctx = 0;
        } else {
            fprintf(stderr, "%.*s%.*s",
                            (int)buf.length, (char *)buf.value,
                            msgctx, " ");
            (void)gss_release_buffer(&retmin, &buf);
        }
    } while (msgctx);
}

int test_Errors(void)
{
    int i;
    for (i = ERR_BASE; i < ERR_LAST; i++) {
        fprintf(stderr, "%x: ", i);
        print_min_status(i);
        fprintf(stderr, "\n");
    }
    return 0;
}

static void print_gss_error(const char *text, uint32_t maj, uint32_t min)
{

    fprintf(stderr, "%s Major Error: [%s] Minor Error: [",
                    text, gss_maj_to_str(maj));
    print_min_status(min);
    fprintf(stderr, "]\n");
    fflush(stderr);
}

int test_gssapi_1(bool user_env_file, bool use_cb, bool no_seal)
{
    gss_ctx_id_t cli_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t srv_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc cli_token = { 0 };
    gss_buffer_desc srv_token = { 0 };
    gss_cred_id_t cli_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t srv_cred = GSS_C_NO_CREDENTIAL;
    const char *username;
    const char *password = "testpassword";
    const char *srvname = "test@testserver";
    gss_name_t gss_username = NULL;
    gss_name_t gss_srvname = NULL;
    gss_buffer_desc pwbuf;
    gss_buffer_desc nbuf;
    uint32_t retmin, retmaj;
    const char *msg = "Sample, payload checking, message.";
    gss_buffer_desc message = { strlen(msg), discard_const(msg) };
    gss_buffer_desc ctx_token;
    gss_OID actual_mech = GSS_C_NO_OID;
    uint8_t rand_cb[128];
    struct gss_channel_bindings_struct cbts = { 0 };
    gss_channel_bindings_t cbt = GSS_C_NO_CHANNEL_BINDINGS;
    gss_buffer_set_t data_set = NULL;
    gss_OID_desc sasl_ssf_oid = {
        11, discard_const("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f")
    };
    uint32_t ssf, expect_ssf;
    uint32_t req_flags;
    int conf_state;
    int ret;

    setenv("NTLM_USER_FILE", TEST_USER_FILE, 0);

    username = getenv("TEST_USER_NAME");
    if (username == NULL) {
        username = "TESTDOM\\testuser";
    }
    nbuf.value = discard_const(username);
    nbuf.length = strlen(username);
    retmaj = gssntlm_import_name(&retmin, &nbuf,
                                 GSS_C_NT_USER_NAME,
                                 &gss_username);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_name(username) failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    if (user_env_file) {
        retmaj = gssntlm_acquire_cred(&retmin, (gss_name_t)gss_username,
                                      GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                      GSS_C_INITIATE, &cli_cred, NULL, NULL);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_acquire_cred(username) failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
    } else {
        pwbuf.value = discard_const(password);
        pwbuf.length = strlen(password);
        retmaj = gssntlm_acquire_cred_with_password(&retmin,
                                                    (gss_name_t)gss_username,
                                                    (gss_buffer_t)&pwbuf,
                                                    GSS_C_INDEFINITE,
                                                    GSS_C_NO_OID_SET,
                                                    GSS_C_INITIATE,
                                                    &cli_cred, NULL, NULL);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_acquire_cred_with_password failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
    }

    retmaj = gssntlm_inquire_cred_by_mech(&retmin, cli_cred, GSS_C_NO_OID,
                                          NULL, NULL, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_cred_by_mech failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    nbuf.value = discard_const(srvname);
    nbuf.length = strlen(srvname);
    retmaj = gssntlm_import_name(&retmin, &nbuf,
                                 GSS_C_NT_HOSTBASED_SERVICE,
                                 &gss_srvname);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_name(srvname) failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    retmaj = gssntlm_acquire_cred(&retmin, (gss_name_t)gss_srvname,
                                  GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                  GSS_C_ACCEPT, &srv_cred, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_acquire_cred(srvname) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    if (use_cb) {
        /* generate random cb */
        cbts.application_data.length = repeatable_rand(rand_cb, 128);
        cbts.application_data.value = rand_cb;
        cbt = &cbts;
    }

    if (no_seal) {
        req_flags = GSS_C_INTEG_FLAG;
    } else {
        req_flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    }

    retmaj = gssntlm_init_sec_context(&retmin, cli_cred, &cli_ctx,
                                      gss_srvname, GSS_C_NO_OID,
                                      req_flags, 0, cbt,
                                      GSS_C_NO_BUFFER, NULL, &cli_token,
                                      NULL, NULL);
    if (retmaj != GSS_S_CONTINUE_NEEDED) {
        print_gss_error("gssntlm_init_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_accept_sec_context(&retmin, &srv_ctx, srv_cred,
                                        &cli_token, cbt,
                                        NULL, NULL, &srv_token,
                                        NULL, NULL, NULL);
    if (retmaj != GSS_S_CONTINUE_NEEDED) {
        print_gss_error("gssntlm_accept_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &cli_token);

    /* test importing and exporting context before it is fully estabished */
    retmaj = gssntlm_export_sec_context(&retmin, &srv_ctx, &ctx_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_export_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }
    retmaj = gssntlm_import_sec_context(&retmin, &ctx_token, &srv_ctx);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }
    gss_release_buffer(&retmin, &ctx_token);

    retmaj = gssntlm_init_sec_context(&retmin, cli_cred, &cli_ctx,
                                      gss_srvname, GSS_C_NO_OID,
                                      req_flags, 0, cbt,
                                      &srv_token, &actual_mech, &cli_token,
                                      NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_init_sec_context 2 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    if (!actual_mech) {
        fprintf(stderr, "Expected actual mech to be returned!\n");
        ret = EINVAL;
        goto done;
    }
    actual_mech = GSS_C_NO_OID;

    gss_release_buffer(&retmin, &srv_token);

    retmaj = gssntlm_accept_sec_context(&retmin, &srv_ctx, srv_cred,
                                        &cli_token, cbt,
                                        NULL, &actual_mech, &srv_token,
                                        NULL, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_accept_sec_context 2 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    if (!actual_mech) {
        fprintf(stderr, "Expected actual mech to be returned!\n");
        ret = EINVAL;
        goto done;
    }
    actual_mech = GSS_C_NO_OID;

    gss_release_buffer(&retmin, &cli_token);
    gss_release_buffer(&retmin, &srv_token);

    /* test importing and exporting context after it is fully estabished */
    retmaj = gssntlm_export_sec_context(&retmin, &cli_ctx, &ctx_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_export_sec_context 2 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }
    retmaj = gssntlm_import_sec_context(&retmin, &ctx_token, &cli_ctx);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_sec_context 2 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }
    gss_release_buffer(&retmin, &ctx_token);

    retmaj = gssntlm_get_mic(&retmin, cli_ctx, 0, &message, &cli_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_get_mic(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_verify_mic(&retmin, srv_ctx, &message, &cli_token, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_verify_mic(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &cli_token);

    retmaj = gssntlm_get_mic(&retmin, srv_ctx, 0, &message, &srv_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_get_mic(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_verify_mic(&retmin, cli_ctx, &message, &srv_token, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_verify_mic(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &srv_token);

    if (no_seal) {
        retmaj = gssntlm_wrap(&retmin, cli_ctx, 1, 0, &message, NULL,
                              &cli_token);
        if ((retmaj != GSS_S_FAILURE) && (retmin != ENOTSUP)) {
            fprintf(stderr, "WARN: gssntlm_wrap(cli) did not fail!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }

        retmaj = gssntlm_wrap(&retmin, srv_ctx, 1, 0, &message, NULL,
                              &srv_token);
        if ((retmaj != GSS_S_FAILURE) && (retmin != ENOTSUP)) {
            fprintf(stderr, "WARN: gssntlm_wrap(srv) did not fail!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }
    } else {
        retmaj = gssntlm_wrap(&retmin, cli_ctx, 1, 0, &message, &conf_state,
                              &cli_token);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_wrap(cli) failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
        if (conf_state == 0) {
            fprintf(stderr, "WARN: gssntlm_wrap(cli) gave 0 conf_state!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }

        retmaj = gssntlm_unwrap(&retmin, srv_ctx,
                                &cli_token, &srv_token, &conf_state, NULL);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_unwrap(srv) failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
        if (conf_state == 0) {
            fprintf(stderr, "WARN: gssntlm_wrap(srv) gave 0 conf_state!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }

        gss_release_buffer(&retmin, &cli_token);
        gss_release_buffer(&retmin, &srv_token);

        retmaj = gssntlm_wrap(&retmin, srv_ctx, 1, 0, &message, &conf_state,
                              &srv_token);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_wrap(srv) failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
        if (conf_state == 0) {
            fprintf(stderr, "WARN: gssntlm_wrap(srv) gave 0 conf_state!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }

        retmaj = gssntlm_unwrap(&retmin, cli_ctx,
                                &srv_token, &cli_token, &conf_state, NULL);
        if (retmaj != GSS_S_COMPLETE) {
            print_gss_error("gssntlm_unwrap(cli) failed!",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }
        if (conf_state == 0) {
            fprintf(stderr, "WARN: gssntlm_wrap(cli) gave 0 conf_state!\n");
            fflush(stderr);
            ret = EINVAL;
            goto done;
        }

        if (memcmp(message.value, cli_token.value, cli_token.length) != 0) {
            print_gss_error("sealing and unsealing failed to return the "
                            "same result",
                            retmaj, retmin);
            ret = EINVAL;
            goto done;
        }

        gss_release_buffer(&retmin, &cli_token);
        gss_release_buffer(&retmin, &srv_token);
    }

    gssntlm_release_name(&retmin, &gss_username);
    gssntlm_release_name(&retmin, &gss_srvname);

    retmaj = gssntlm_inquire_context(&retmin, srv_ctx,
                                     &gss_username, &gss_srvname,
                                     NULL, NULL, NULL, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_inquire_context failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_display_name(&retmin, gss_username, &nbuf, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_display_name failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    if (strcmp(nbuf.value, username) != 0) {
        fprintf(stderr, "Expected username of [%s] but got [%s] instead!\n",
                        username, (char *)nbuf.value);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &nbuf);

    retmaj = gssntlm_inquire_sec_context_by_oid(&retmin, srv_ctx,
                                                &sasl_ssf_oid, &data_set);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_inquire_sec_context_by_oid failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }
    if (data_set == NULL || data_set->count != 1) {
        fprintf(stderr, "Expected 1 data_set element\n");
        return EINVAL;
    }
    ssf = be32toh(*(uint32_t *)data_set->elements[0].value);
    expect_ssf = 64;
    if (no_seal) {
        expect_ssf = 1;
    }
    if (ssf != expect_ssf) {
        fprintf(stderr, "Expected SSF of %u, got: %u\n",
                (unsigned int)expect_ssf, (unsigned int)ssf);
        return EINVAL;
    }

    ret = 0;

done:
    gssntlm_delete_sec_context(&retmin, &cli_ctx, GSS_C_NO_BUFFER);
    gssntlm_delete_sec_context(&retmin, &srv_ctx, GSS_C_NO_BUFFER);
    gssntlm_release_name(&retmin, &gss_username);
    gssntlm_release_name(&retmin, &gss_srvname);
    gssntlm_release_cred(&retmin, &cli_cred);
    gssntlm_release_cred(&retmin, &srv_cred);
    gss_release_buffer(&retmin, &cli_token);
    gss_release_buffer(&retmin, &srv_token);
    gss_release_buffer_set(&retmin, &data_set);
    return ret;
}

int test_gssapi_cl(void)
{
    gss_ctx_id_t cli_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t srv_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc cli_token = { 0 };
    gss_buffer_desc srv_token = { 0 };
    gss_cred_id_t cli_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t srv_cred = GSS_C_NO_CREDENTIAL;
    const char *username;
    const char *password = "testpassword";
    const char *srvname = "test@testserver";
    gss_name_t gss_username = NULL;
    gss_name_t gss_srvname = NULL;
    gss_buffer_desc pwbuf;
    gss_buffer_desc nbuf;
    gss_OID_desc set_seqnum_oid = {
        GSS_NTLMSSP_SET_SEQ_NUM_OID_LENGTH,
        discard_const(GSS_NTLMSSP_SET_SEQ_NUM_OID_STRING)
    };
    gss_buffer_desc set_seqnum_buf;
    uint32_t app_seq_num;
    uint32_t retmin, retmaj;
    const char *msg = "Sample, signature checking, message.";
    gss_buffer_desc message = { strlen(msg), discard_const(msg) };
    int ret;

    setenv("NTLM_USER_FILE", TEST_USER_FILE, 0);

    username = getenv("TEST_USER_NAME");
    if (username == NULL) {
        username = "TESTDOM\\testuser";
    }
    nbuf.value = discard_const(username);
    nbuf.length = strlen(username);
    retmaj = gssntlm_import_name(&retmin, &nbuf,
                                 GSS_C_NT_USER_NAME,
                                 &gss_username);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_name(username) failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    pwbuf.value = discard_const(password);
    pwbuf.length = strlen(password);
    retmaj = gssntlm_acquire_cred_with_password(&retmin,
                                                (gss_name_t)gss_username,
                                                (gss_buffer_t)&pwbuf,
                                                GSS_C_INDEFINITE,
                                                GSS_C_NO_OID_SET,
                                                GSS_C_INITIATE,
                                                &cli_cred, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_acquire_cred_with_password failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    nbuf.value = discard_const(srvname);
    nbuf.length = strlen(srvname);
    retmaj = gssntlm_import_name(&retmin, &nbuf,
                                 GSS_C_NT_HOSTBASED_SERVICE,
                                 &gss_srvname);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_import_name(srvname) failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    retmaj = gssntlm_acquire_cred(&retmin, (gss_name_t)gss_srvname,
                                  GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                  GSS_C_ACCEPT, &srv_cred, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_acquire_cred(srvname) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_accept_sec_context(&retmin, &srv_ctx, srv_cred,
                                        &cli_token, GSS_C_NO_CHANNEL_BINDINGS,
                                        NULL, NULL, &srv_token,
                                        NULL, NULL, NULL);
    if (retmaj != GSS_S_CONTINUE_NEEDED) {
        print_gss_error("gssntlm_accept_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &cli_token);

    retmaj = gssntlm_init_sec_context(&retmin, cli_cred, &cli_ctx,
                                      gss_srvname, GSS_C_NO_OID,
                                      GSS_C_CONF_FLAG |
                                          GSS_C_INTEG_FLAG |
                                          GSS_C_DATAGRAM_FLAG,
                                      0, GSS_C_NO_CHANNEL_BINDINGS,
                                      &srv_token, NULL, &cli_token,
                                      NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_init_sec_context 1 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &srv_token);

    retmaj = gssntlm_accept_sec_context(&retmin, &srv_ctx, srv_cred,
                                        &cli_token, GSS_C_NO_CHANNEL_BINDINGS,
                                        NULL, NULL, &srv_token,
                                        NULL, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_accept_sec_context 2 failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    /* TODO: again with channel bindings */

    gss_release_buffer(&retmin, &cli_token);
    gss_release_buffer(&retmin, &srv_token);

    /* arbitrary seq number forced on the context */
    app_seq_num = 10;
    set_seqnum_buf.value = &app_seq_num;
    set_seqnum_buf.length = 4;
    retmaj = gssntlm_set_sec_context_option(&retmin, (gss_ctx_id_t *)&cli_ctx,
                                            &set_seqnum_oid,
                                            &set_seqnum_buf);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_set_sec_context_option(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_set_sec_context_option(&retmin, (gss_ctx_id_t *)&srv_ctx,
                                            &set_seqnum_oid,
                                            &set_seqnum_buf);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_set_sec_context_option(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_get_mic(&retmin, cli_ctx, 0, &message, &cli_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_get_mic(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_verify_mic(&retmin, srv_ctx, &message, &cli_token, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_verify_mic(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &cli_token);

    retmaj = gssntlm_get_mic(&retmin, srv_ctx, 0, &message, &srv_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_get_mic(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_verify_mic(&retmin, cli_ctx, &message, &srv_token, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_verify_mic(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &srv_token);

    retmaj = gssntlm_wrap(&retmin, cli_ctx, 1, 0, &message, NULL, &cli_token);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_wrap(cli) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    retmaj = gssntlm_unwrap(&retmin, srv_ctx,
                            &cli_token, &srv_token, NULL, NULL);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_unwrap(srv) failed!",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    if (memcmp(message.value, srv_token.value, srv_token.length) != 0) {
        print_gss_error("sealing and unsealing failed to return the "
                        "same result",
                        retmaj, retmin);
        ret = EINVAL;
        goto done;
    }

    gss_release_buffer(&retmin, &cli_token);
    gss_release_buffer(&retmin, &srv_token);

    gssntlm_release_name(&retmin, &gss_username);
    gssntlm_release_name(&retmin, &gss_srvname);

    ret = 0;

done:
    gssntlm_delete_sec_context(&retmin, &cli_ctx, GSS_C_NO_BUFFER);
    gssntlm_delete_sec_context(&retmin, &srv_ctx, GSS_C_NO_BUFFER);
    gssntlm_release_name(&retmin, &gss_username);
    gssntlm_release_name(&retmin, &gss_srvname);
    gssntlm_release_cred(&retmin, &cli_cred);
    gssntlm_release_cred(&retmin, &srv_cred);
    gss_release_buffer(&retmin, &cli_token);
    gss_release_buffer(&retmin, &srv_token);
    return ret;
}

int test_gssapi_rfc5801(void)
{
    gss_buffer_desc sasl_name = { 8, discard_const("GS2-NTLM") };
    gss_buffer_desc mech_name;
    gss_buffer_desc mech_desc;
    gss_OID oid;
    uint32_t retmin, retmaj;

    retmaj = gssntlm_inquire_mech_for_saslname(&retmin, &sasl_name, &oid);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_inquire_mech_for_saslname() failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    retmaj = gssntlm_inquire_saslname_for_mech(&retmin, oid, &sasl_name,
                                               &mech_name, &mech_desc);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_inquire_saslname_for_mech() failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    if (strncmp(sasl_name.value, "GS2-NTLM", 8)) {
        fprintf(stderr, "Expected 'GS2-NTLM', got: '%.*s'\n",
                (int)sasl_name.length, (char *)sasl_name.value);
        return EINVAL;
    }

    if (strncmp(mech_name.value, "NTLM", 8)) {
        fprintf(stderr, "Expected 'NTLM', got: '%.*s'\n",
                (int)mech_name.length, (char *)mech_name.value);
        return EINVAL;
    }

    if (strncmp(mech_desc.value, "NTLM Mechanism", 8)) {
        fprintf(stderr, "Expected 'NTLM Mechanism', got: '%.*s'\n",
                (int)mech_desc.length, (char *)mech_desc.value);
        return EINVAL;
    }

    return 0;
}

int test_gssapi_rfc5587(void)
{
    gss_OID_set mech_attrs;
    gss_OID_set known_mech_attrs;
    uint32_t retmin, retmaj;

    retmaj = gssntlm_inquire_attrs_for_mech(&retmin, &gssntlm_oid,
                                            &mech_attrs, &known_mech_attrs);
    if (retmaj != GSS_S_COMPLETE) {
        print_gss_error("gssntlm_inquire_attrs_for_mech() failed!",
                        retmaj, retmin);
        return EINVAL;
    }

    if (mech_attrs == GSS_C_NULL_OID_SET) {
        fprintf(stderr, "mech_attrs returned empty\n");
        return EINVAL;
    }

    if (known_mech_attrs == GSS_C_NULL_OID_SET) {
        fprintf(stderr, "known_mech_attrs returned empty\n");
        return EINVAL;
    }

    if (mech_attrs->count != 9) {
        fprintf(stderr, "expected 9 mech_attr oids, got %lu\n",
                mech_attrs->count);
        return EINVAL;
    }

#define CHECK_MA(A, X) \
do { \
    int i; \
    for (i = 0; i < A->count; i++) { \
        if ((A->elements[i].length == X->length) && \
            (memcmp(A->elements[i].elements, \
                    X->elements, X->length) == 0)) break; \
    } \
    if (i >= A->count) { \
        fprintf(stderr, #X " is missing from " #A " set\n"); \
        return EINVAL; \
    } \
} while(0)

    CHECK_MA(mech_attrs, GSS_C_MA_MECH_CONCRETE);
    CHECK_MA(mech_attrs, GSS_C_MA_AUTH_INIT);
    CHECK_MA(mech_attrs, GSS_C_MA_INTEG_PROT);
    CHECK_MA(mech_attrs, GSS_C_MA_CONF_PROT);
    CHECK_MA(mech_attrs, GSS_C_MA_MIC);
    CHECK_MA(mech_attrs, GSS_C_MA_WRAP);
    CHECK_MA(mech_attrs, GSS_C_MA_OOS_DET);
    CHECK_MA(mech_attrs, GSS_C_MA_CBINDINGS);
    CHECK_MA(mech_attrs, GSS_C_MA_CTX_TRANS);

    if (known_mech_attrs->count != 27) {
        fprintf(stderr, "expected 27 known_mech_attr oids, got %lu\n",
                known_mech_attrs->count);
        return EINVAL;
    }

    CHECK_MA(known_mech_attrs, GSS_C_MA_MECH_CONCRETE);
    CHECK_MA(known_mech_attrs, GSS_C_MA_MECH_PSEUDO);
    CHECK_MA(known_mech_attrs, GSS_C_MA_MECH_COMPOSITE);
    CHECK_MA(known_mech_attrs, GSS_C_MA_MECH_NEGO);
    CHECK_MA(known_mech_attrs, GSS_C_MA_MECH_GLUE);
    CHECK_MA(known_mech_attrs, GSS_C_MA_NOT_MECH);
    CHECK_MA(known_mech_attrs, GSS_C_MA_DEPRECATED);
    CHECK_MA(known_mech_attrs, GSS_C_MA_NOT_DFLT_MECH);
    CHECK_MA(known_mech_attrs, GSS_C_MA_ITOK_FRAMED);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_INIT);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_TARG);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_INIT_INIT);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_TARG_INIT);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_INIT_ANON);
    CHECK_MA(known_mech_attrs, GSS_C_MA_AUTH_TARG_ANON);
    CHECK_MA(known_mech_attrs, GSS_C_MA_DELEG_CRED);
    CHECK_MA(known_mech_attrs, GSS_C_MA_INTEG_PROT);
    CHECK_MA(known_mech_attrs, GSS_C_MA_CONF_PROT);
    CHECK_MA(known_mech_attrs, GSS_C_MA_MIC);
    CHECK_MA(known_mech_attrs, GSS_C_MA_WRAP);
    CHECK_MA(known_mech_attrs, GSS_C_MA_PROT_READY);
    CHECK_MA(known_mech_attrs, GSS_C_MA_REPLAY_DET);
    CHECK_MA(known_mech_attrs, GSS_C_MA_OOS_DET);
    CHECK_MA(known_mech_attrs, GSS_C_MA_CBINDINGS);
    CHECK_MA(known_mech_attrs, GSS_C_MA_PFS);
    CHECK_MA(known_mech_attrs, GSS_C_MA_COMPRESS);
    CHECK_MA(known_mech_attrs, GSS_C_MA_CTX_TRANS);

    return 0;
}

/* test with data from Jordan Borean, the DC apparently has a zero key */
int test_ZERO_LMKEY(struct ntlm_ctx *ctx)
{
    struct ntlm_key lmowf = { .data = {0}, .length = 16 };
    struct ntlm_key ntowf = { .length = 16 };
    struct ntlm_key sessionkey = { .length = 16 };
    struct ntlm_key result = { .length = 16 };
    const char *password = "VagrantPass1";
    uint8_t serverChallenge[] = {
        0x45, 0x56, 0xB5, 0x69, 0xC9, 0x53, 0x6A, 0x31
    };
    struct ntlm_key MS_SessionKey = {
        .data = {
            0x5F, 0xFA, 0x2B, 0xF7, 0x27, 0xAD, 0xD1, 0x01,
            0xC2, 0x6C, 0xF2, 0xE6, 0xC1, 0x13, 0xBD, 0x6D
        },
        .length = 16
    };
    uint8_t LM_Response[] = {
        0x8B, 0xFC, 0xFE, 0xD5, 0xA3, 0x6D, 0x25, 0x13,
        0x86, 0xCC, 0x38, 0xDE, 0x78, 0xBA, 0xE1, 0x62,
        0x24, 0xC5, 0x2F, 0xD7, 0x35, 0x35, 0x5E, 0x24
    };
    struct ntlm_buffer lm_response = {
        .data = LM_Response,
        .length = 24
    };
    int ret;

    ret = NTOWFv1(password, &ntowf);
    if (ret) return ret;
    ret = ntlm_session_base_key(&ntowf, &sessionkey);
    if (ret) return ret;

    ret = KXKEY(ctx, false, true, false, serverChallenge, &lmowf,
                &sessionkey, &lm_response, &result);
    if (ret) return ret;

    return test_keys("results", &MS_SessionKey, &result);
}

int test_NTOWF_UTF16(struct ntlm_ctx *ctx)
{
    const char *passwd = "Pass\xF0\x9D\x84\x9E";
    struct ntlm_key expected = {
        .data = {
            0x0d, 0x72, 0xdd, 0xde, 0xdd, 0xba, 0xe5, 0xff,
            0x24, 0x48, 0x20, 0xe0, 0x72, 0x41, 0x3b, 0x90
        },
        .length = 16
    };
    struct ntlm_key result = { .length = 16 };
    int ret;

    ret = NTOWFv1(passwd, &result);
    if (ret) return ret;

    return test_keys("results", &expected, &result);
}

int main(int argc, const char *argv[])
{
    struct ntlm_ctx *ctx;
    int gret = 0;
    int ret;

    /* enable trace debugging by dfault in tests */
    setenv("GSSNTLMSSP_DEBUG", "tests-trace.log", 0);

    fprintf(stderr, "Test errors\n");
    ret = test_Errors();
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    ret = ntlm_init_ctx(&ctx);
    if (ret) goto done;

    fprintf(stderr, "Test LMOWFv1\n");
    ret = test_LMOWFv1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test NTOWFv1\n");
    ret = test_NTOWFv1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test LMResponse v1\n");
    ret = test_LMResponseV1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test NTResponse v1\n");
    ret = test_NTResponseV1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test SessionBaseKey v1\n");
    ret = test_SessionBaseKeyV1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test LM KeyExchangeKey\n");
    ret = test_LM_KeyExchangeKey(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test EncryptedSessionKey v1 (1)\n");
    ret = test_EncryptedSessionKey1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test EncryptedSessionKey v1 (2)\n");
    ret = test_EncryptedSessionKey2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test EncryptedSessionKey v1 (3)\n");
    ret = test_EncryptedSessionKey3(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    /* override internal version for V1 test vector */
    ntlm_internal_set_version(6, 0, 6000, 15);

    fprintf(stderr, "Test decoding ChallengeMessage v1\n");
    ret = test_DecodeChallengeMessageV1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test encoding ChallengeMessage v1\n");
    ret = test_EncodeChallengeMessageV1(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test LMResponse v2\n");
    ret = test_LMResponseV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test NTResponse v2\n");
    ret = test_NTResponseV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test SessionBaseKey v2\n");
    ret = test_SessionBaseKeyV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test EncryptedSessionKey v2\n");
    ret = test_EncryptedSessionKey(ctx, &T_NTLMv2.SessionBaseKey,
                                   &T_NTLMv2.EncryptedSessionKey);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    /* override internal version for V2 test vector */
    ntlm_internal_set_version(6, 0, 6000, 15);

    fprintf(stderr, "Test decoding ChallengeMessage v2\n");
    ret = test_DecodeChallengeMessageV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test encoding ChallengeMessage v2\n");
    ret = test_EncodeChallengeMessageV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test decoding AuthenticateMessage v2\n");
    ret = test_DecodeAuthenticateMessageV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test encoding AuthenticateMessage v2\n");
    ret = test_EncodeAuthenticateMessageV2(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    /* override internal version for CBT test vector */
    ntlm_internal_set_version(6, 1, 7600, 15);

    fprintf(stderr, "Test decoding ChallengeMessage v2 with CBT\n");
    ret = test_DecodeChallengeMessageV2CBT(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test encoding ChallengeMessage v2 with CBT\n");
    ret = test_EncodeChallengeMessageV2CBT(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test decoding AuthenticateMessage v2 with CBT\n");
    ret = test_DecodeAuthenticateMessageV2CBT(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test sealing a Message with No Extended Security\n");
    ret = test_GSS_Wrap_EX(ctx, &T_GSSWRAPv1noESS);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test sealing a Message with NTLMv1 Extended Security\n");
    ret = test_GSS_Wrap_EX(ctx, &T_GSSWRAPEXv1);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test sealing a Message with NTLMv2 Extended Security\n");
    ret = test_GSS_Wrap_EX(ctx, &T_GSSWRAPEXv2);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, " *** Test with NTLMv1 auth\n");
    setenv("LM_COMPAT_LEVEL", "0", 1);

    fprintf(stderr, "Test GSSAPI conversation (user env file)\n");
    ret = test_gssapi_1(true, false, false);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test GSSAPI conversation (no SEAL)\n");
    ret = test_gssapi_1(true, false, true);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test GSSAPI conversation (with password)\n");
    ret = test_gssapi_1(false, false, false);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test Connectionless exchange\n");
    ret = test_gssapi_cl();
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, " *** Again forcing NTLMv2 auth\n");
    setenv("LM_COMPAT_LEVEL", "5", 1);

    fprintf(stderr, "Test GSSAPI conversation (user env file)\n");
    ret = test_gssapi_1(true, false, false);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test GSSAPI conversation (no SEAL)\n");
    ret = test_gssapi_1(true, false, true);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test GSSAPI conversation (with password)\n");
    ret = test_gssapi_1(false, false, false);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test GSSAPI conversation (with CB)\n");
    ret = test_gssapi_1(false, true, false);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test Connectionless exchange\n");
    ret = test_gssapi_cl();
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test RFC5801 SPI\n");
    ret = test_gssapi_rfc5801();
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test RFC5587 SPI\n");
    ret = test_gssapi_rfc5587();
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test ZERO LM_KEY\n");
    ret = test_ZERO_LMKEY(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

    fprintf(stderr, "Test NTOWF iwith UTF16\n");
    ret = test_NTOWF_UTF16(ctx);
    fprintf(stderr, "Test: %s\n", (ret ? "FAIL":"SUCCESS"));
    if (ret) gret++;

done:
    ntlm_free_ctx(&ctx);
    return gret;
}
