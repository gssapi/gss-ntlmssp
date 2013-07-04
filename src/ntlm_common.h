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

#ifndef _NTLM_COMMON_H_
#define _NTLM_COMMON_H_

#include <stdint.h>
#include <stdlib.h>

enum ntlm_err_code {
    ERR_BASE = 0x4E540000, /* base error space at 'NT00' */
    ERR_DECODE,
    ERR_ENCODE,
    ERR_CRYPTO,
};
#define NTLM_ERR_MASK 0x4E54FFFF
#define IS_NTLM_ERR_CODE(x) (((x) & NTLM_ERR_MASK) ? true : false)

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define safefree(x) do { free(x); x = NULL; } while(0)
#define safezero(x, s) do { \
    volatile uint8_t *p = (x); \
    size_t size = (s); \
    while (size--) { *p++ = 0; } \
} while(0)


struct ntlm_buffer {
    uint8_t *data;
    size_t length;
};

struct ntlm_rc4_handle;

enum ntlm_cipher_mode {
    NTLM_CIPHER_IGNORE,
    NTLM_CIPHER_ENCRYPT,
    NTLM_CIPHER_DECRYPT,
};

#endif /* _NTLM_COMMON_H_ */
