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

#ifndef _GSSAPI_NTLMSSP_H_
#define _GSSAPI_NTLMSSP_H_

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10 */
#define GSS_NTLMSSP_OID_STRING "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
#define GSS_NTLMSSP_OID_LENGTH 10

/* add a new GSSPAPI req flag, it is technically a sort of SSPI
 * extension as Microsoft's SSPI may change behavior on datagram
 * oriented connections and has a ISC_REQ_DATAGRAM flag for that */
#define GSS_C_DATAGRAM_FLAG 0x10000

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GSSAPI_NTLMSSP_H_ */
