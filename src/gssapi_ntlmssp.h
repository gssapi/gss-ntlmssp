/* Copyright 2013 Simo Sorce <simo@samba.org>, see COPYING for license */

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


/* OID space kindly donated by Samba Project: 1.3.6.1.4.1.7165.655.1 */
#define GSS_NTLMSSP_BASE_OID_STRING "\x2b\x06\x01\x04\x01\xb7\x7d\x85\x0f\x01"
#define GSS_NTLMSSP_BASE_OID_LENGTH 10

/* Set Seq Num OID
 * OID to be used to be used with gss_set_sec_context_option()
 * the value buffer is a uint32_t in host order and is used
 * to force a specific sequence number. This operation is allowed
 * only if GSS_C_DATAGRAM_FLAG was used. */
#define GSS_NTLMSSP_SET_SEQ_NUM_OID_STRING GSS_NTLMSSP_BASE_OID_STRING "\x01"
#define GSS_NTLMSSP_SET_SEQ_NUM_OID_LENGTH GSS_NTLMSSP_BASE_OID_LENGTH + 1

/* SPNEGO Require MIC OID
 * When the NTLMSSP mechanism produces a MIC in the authenticate message,
 * the SPNEGO mechanism also must produce a mechlistMIC token otherwise
 * Windows servers get confused and fail the authentication.
 * This OID is queried by the SPNEGO mechanism after each token is generated.
 * After the Negotiate token is produced, a query for this context property
 * signals us that the SPNEGO implementation knows how to deal with the MIC,
 * After the Authenticate token is produced we return whether a MIC was
 * produced or not */
#define GSS_SPNEGO_REQUIRE_MIC_OID_STRING GSS_NTLMSSP_BASE_OID_STRING "\x02"
#define GSS_SPNEGO_REQUIRE_MIC_OID_LENGTH GSS_NTLMSSP_BASE_OID_LENGTH + 1

/* SPNEGO Reset Crypto OID
 * MS-SPNG 3.3.5.1 warns hat the NTLM mechanism requires to reset the
 * crypto engine when the SPNEGO layer uses a MechListMIC.
 * This OID is queried by the SPNEGO mechanism after a MIC processing to
 * cause the crypto engine to be reset.
 */
#define GSS_NTLMSSP_RESET_CRYPTO_OID_STRING GSS_NTLMSSP_BASE_OID_STRING "\x03"
#define GSS_NTLMSSP_RESET_CRYPTO_OID_LENGTH GSS_NTLMSSP_BASE_OID_LENGTH + 1

#define GSS_NTLMSSP_CS_DOMAIN "ntlmssp_domain"
#define GSS_NTLMSSP_CS_NTHASH "ntlmssp_nthash"
#define GSS_NTLMSSP_CS_PASSWORD "ntlmssp_password"
#define GSS_NTLMSSP_CS_KEYFILE "ntlmssp_keyfile"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GSSAPI_NTLMSSP_H_ */
