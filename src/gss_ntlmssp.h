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

#ifndef _GSS_NTLMSSP_H_
#define _GSS_NTLMSSP_H_

#include "ntlm.h"
#include "crypto.h"
#include "gssapi_ntlmssp.h"

#define MAX_CHALRESP_LIFETIME 36 * 60 * 60 /* 36 hours in seconds */

#define SEC_LEVEL_MIN 0
#define SEC_LEVEL_MAX 5

#define SEC_LM_OK 0x01
#define SEC_NTLM_OK 0x02
#define SEC_EXT_SEC_OK 0x04
#define SEC_V2_ONLY 0x08
#define SEC_DC_LM_OK 0x10
#define SEC_DC_NTLM_OK 0x20
#define SEC_DC_V2_OK 0x40

#define NTLMSSP_DEFAULT_CLIENT_FLAGS ( \
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                NTLMSSP_NEGOTIATE_128 | \
                NTLMSSP_NEGOTIATE_56 | \
                NTLMSSP_NEGOTIATE_NTLM | \
                NTLMSSP_REQUEST_TARGET | \
                NTLMSSP_NEGOTIATE_UNICODE)

#define NTLMSSP_DEFAULT_ALLOWED_SERVER_FLAGS ( \
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                NTLMSSP_NEGOTIATE_56 | \
                NTLMSSP_NEGOTIATE_KEY_EXCH | \
                NTLMSSP_NEGOTIATE_128 | \
                NTLMSSP_NEGOTIATE_VERSION | \
                NTLMSSP_TARGET_TYPE_SERVER | \
                NTLMSSP_TARGET_TYPE_DOMAIN | \
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED | \
                NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | \
                NTLMSSP_NEGOTIATE_NTLM | \
                NTLMSSP_NEGOTIATE_SEAL | \
                NTLMSSP_NEGOTIATE_SIGN | \
                NTLMSSP_REQUEST_TARGET | \
                NTLMSSP_NEGOTIATE_OEM | \
                NTLMSSP_NEGOTIATE_UNICODE)

#define NTLMSSP_CTX_FLAG_ESTABLISHED    0x01 /* context was established */
#define NTLMSSP_CTX_FLAG_SPNEGO_CAN_MIC 0x02 /* SPNEGO asks for MIC */
#define NTLMSSP_CTX_FLAG_AUTH_WITH_MIC  0x04 /* Auth MIC was created */

struct gssntlm_name {
    enum ntlm_name_type {
        GSSNTLM_NAME_NULL,
        GSSNTLM_NAME_ANON,
        GSSNTLM_NAME_USER,
        GSSNTLM_NAME_SERVER
    } type;

    union {
        struct {
            char *domain;
            char *name;
        } user;
        struct {
            char *name;
        } server;
    } data;
};

struct gssntlm_cred {
    enum ntlm_cred_type {
        GSSNTLM_CRED_NONE,
        GSSNTLM_CRED_ANON,
        GSSNTLM_CRED_USER,
        GSSNTLM_CRED_SERVER,
        GSSNTLM_CRED_EXTERNAL,
    } type;

    union {
        struct {
            int dummy;
        } anon;
        struct {
            struct gssntlm_name user;
            struct ntlm_key nt_hash;
            struct ntlm_key lm_hash;
        } user;
        struct {
            struct gssntlm_name name;
        } server;
        struct {
            struct gssntlm_name user;
        } external;
    } cred;
};

struct gssntlm_ctx {
    enum gssntlm_role {
        GSSNTLM_CLIENT,
        GSSNTLM_SERVER,
        GSSNTLM_DOMAIN_SERVER,
        GSSNTLM_DOMAIN_CONTROLLER
    } role;

    enum {
        NTLMSSP_STAGE_INIT = 0,
        NTLMSSP_STAGE_NEGOTIATE,
        NTLMSSP_STAGE_CHALLENGE,
        NTLMSSP_STAGE_AUTHENTICATE,
        NTLMSSP_STAGE_DONE
    } stage;

    uint8_t sec_req;

    char *workstation;

    struct ntlm_ctx *ntlm;
    struct ntlm_buffer nego_msg;
    struct ntlm_buffer chal_msg;
    struct ntlm_buffer auth_msg;

    struct gssntlm_name source_name;
    struct gssntlm_name target_name;

    uint8_t server_chal[8];

    /* requested gss fags */
    uint32_t gss_flags;

    /* negotiated flags */
    uint32_t neg_flags;

    /* TODO: Add whitelist of servers we are allowed to communicate with */

    struct ntlm_key exported_session_key;
    struct ntlm_signseal_state crypto_state;

    uint32_t int_flags;
    time_t expiration_time;
};

uint8_t gssntlm_required_security(int security_level,
                                  enum gssntlm_role role);

uint32_t gssntlm_context_is_valid(struct gssntlm_ctx *ctx,
                                  time_t *time_now);

int gssntlm_get_lm_compatibility_level(void);

void gssntlm_int_release_name(struct gssntlm_name *name);
void gssntlm_int_release_cred(struct gssntlm_cred *cred);

int gssntlm_copy_name(struct gssntlm_name *src, struct gssntlm_name *dst);
int gssntlm_copy_creds(struct gssntlm_cred *in, struct gssntlm_cred *out);

uint32_t external_netbios_get_names(char **computer, char **domain);
uint32_t external_get_creds(struct gssntlm_name *name,
                            struct gssntlm_cred *cred);
uint32_t external_cli_auth(struct gssntlm_ctx *ctx,
                           struct gssntlm_cred *cred,
                           uint32_t in_flags,
                           gss_channel_bindings_t input_chan_bindings);
uint32_t external_srv_auth(struct gssntlm_ctx *ctx,
                           struct gssntlm_cred *cred,
                           struct ntlm_buffer *nt_chal_resp,
                           struct ntlm_buffer *lm_chal_resp,
                           struct ntlm_key *session_base_key);

uint32_t netbios_get_names(char *computer_name,
                           char **netbios_host, char **netbios_domain);

bool is_ntlm_v1(struct ntlm_buffer *nt_chal_resp);

uint32_t gssntlm_cli_auth(uint32_t *minor,
                          struct gssntlm_ctx *ctx,
                          struct gssntlm_cred *cred,
                          struct ntlm_buffer *target_info,
                          uint32_t in_flags,
                          gss_channel_bindings_t input_chan_bindings);
uint32_t gssntlm_srv_auth(uint32_t *minor,
                          struct gssntlm_ctx *ctx,
                          struct gssntlm_cred *cred,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *key_exchange_key);

extern const gss_OID_desc gssntlm_oid;

uint32_t gssntlm_acquire_cred(uint32_t *minor_status,
                              gss_name_t desired_name,
                              uint32_t time_req,
                              gss_OID_set desired_mechs,
                              gss_cred_usage_t cred_usage,
                              gss_cred_id_t *output_cred_handle,
                              gss_OID_set *actual_mechs,
                              uint32_t *time_rec);

uint32_t gssntlm_acquire_cred_from(uint32_t *minor_status,
                                   gss_name_t desired_name,
                                   uint32_t time_req,
                                   gss_OID_set desired_mechs,
                                   gss_cred_usage_t cred_usage,
                                   gss_const_key_value_set_t cred_store,
                                   gss_cred_id_t *output_cred_handle,
                                   gss_OID_set *actual_mechs,
                                   uint32_t *time_rec);

uint32_t gssntlm_acquire_cred_with_password(uint32_t *minor_status,
                                            gss_name_t desired_name,
                                            gss_buffer_t password,
                                            uint32_t time_req,
                                            gss_OID_set desired_mechs,
                                            gss_cred_usage_t cred_usage,
                                            gss_cred_id_t *output_cred_handle,
                                            gss_OID_set *actual_mechs,
                                            uint32_t *time_rec);

uint32_t gssntlm_release_cred(uint32_t *minor_status,
                              gss_cred_id_t *cred_handle);

uint32_t gssntlm_import_name(uint32_t *minor_status,
                             gss_buffer_t input_name_buffer,
                             gss_OID input_name_type,
                             gss_name_t *output_name);

uint32_t gssntlm_import_name_by_mech(uint32_t *minor_status,
                                     gss_const_OID mech_type,
                                     gss_buffer_t input_name_buffer,
                                     gss_OID input_name_type,
                                     gss_name_t *output_name);

uint32_t gssntlm_duplicate_name(uint32_t *minor_status,
                                const gss_name_t input_name,
                                gss_name_t *dest_name);

uint32_t gssntlm_release_name(uint32_t *minor_status,
                              gss_name_t *input_name);

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
                                  uint32_t *time_rec);

uint32_t gssntlm_delete_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_buffer_t output_token);


uint32_t gssntlm_context_time(uint32_t *minor_status,
                              gss_ctx_id_t context_handle,
                              uint32_t *time_rec);

uint32_t gssntlm_accept_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_cred_id_t acceptor_cred_handle,
                                    gss_buffer_t input_token_buffer,
                                    gss_channel_bindings_t input_chan_bindings,
                                    gss_name_t *src_name,
                                    gss_OID *mech_type,
                                    gss_buffer_t output_token,
                                    uint32_t *ret_flags,
                                    uint32_t *time_rec,
                                    gss_cred_id_t *delegated_cred_handle);

uint32_t gssntlm_set_sec_context_option(uint32_t *minor_status,
                                        gss_ctx_id_t *context_handle,
                                        const gss_OID desired_object,
                                        const gss_buffer_t value);

uint32_t gssntlm_inquire_sec_context_by_oid(uint32_t *minor_status,
	                                    const gss_ctx_id_t context_handle,
	                                    const gss_OID desired_object,
	                                    gss_buffer_set_t *data_set);

uint32_t gssntlm_get_mic(uint32_t *minor_status,
                         gss_ctx_id_t context_handle,
                         gss_qop_t qop_req,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token);

uint32_t gssntlm_verify_mic(uint32_t *minor_status,
                            gss_ctx_id_t context_handle,
                            gss_buffer_t message_buffer,
                            gss_buffer_t message_token,
                            gss_qop_t *qop_state);

uint32_t gssntlm_wrap(uint32_t *minor_status,
                      gss_ctx_id_t context_handle,
                      int conf_req_flag,
                      gss_qop_t qop_req,
                      gss_buffer_t input_message_buffer,
                      int *conf_state,
                      gss_buffer_t output_message_buffer);

uint32_t gssntlm_unwrap(uint32_t *minor_status,
                        gss_ctx_id_t context_handle,
                        gss_buffer_t input_message_buffer,
                        gss_buffer_t output_message_buffer,
                        int *conf_state,
                        gss_qop_t *qop_state);

uint32_t gssntlm_wrap_size_limit(uint32_t *minor_status,
                                 gss_ctx_id_t context_handle,
                                 int conf_req_flag,
                                 gss_qop_t qop_req,
                                 uint32_t req_output_size,
                                 uint32_t *max_input_size);

uint32_t gssntlm_inquire_context(uint32_t *minor_status,
                                 gss_ctx_id_t context_handle,
                                 gss_name_t *src_name,
                                 gss_name_t *targ_name,
                                 uint32_t *lifetime_rec,
                                 gss_OID *mech_type,
                                 uint32_t *ctx_flags,
                                 int *locally_initiated,
                                 int *open);

uint32_t gssntlm_display_name(uint32_t *minor_status,
                              gss_name_t input_name,
                              gss_buffer_t output_name_buffer,
                              gss_OID *output_name_type);

uint32_t gssntlm_localname(uint32_t *minor_status,
	                   const gss_name_t name,
	                   gss_const_OID mech_type,
	                   gss_buffer_t localname);

uint32_t gssntlm_inquire_cred(uint32_t *minor_status,
                              gss_cred_id_t cred_handle,
                              gss_name_t *name,
                              uint32_t *lifetime,
                              gss_cred_usage_t *cred_usage,
                              gss_OID_set *mechanisms);

uint32_t gssntlm_inquire_cred_by_mech(uint32_t *minor_status,
                                      gss_cred_id_t cred_handle,
                                      gss_OID mech_type,
                                      gss_name_t *name,
                                      uint32_t *initiator_lifetime,
                                      uint32_t *acceptor_lifetime,
                                      gss_cred_usage_t *cred_usage);

uint32_t gssntlm_export_sec_context(uint32_t *minor_status,
                                    gss_ctx_id_t *context_handle,
                                    gss_buffer_t interprocess_token);

uint32_t gssntlm_import_sec_context(uint32_t *minor_status,
                                    gss_buffer_t interprocess_token,
                                    gss_ctx_id_t *context_handle);

uint32_t gssntlm_export_cred(uint32_t *minor_status,
                             gss_cred_id_t cred_handle,
                             gss_buffer_t token);

uint32_t gssntlm_import_cred(uint32_t *minor_status,
                             gss_buffer_t token,
                             gss_cred_id_t *cred_handle);
#endif /* _GSS_NTLMSSP_H_ */
