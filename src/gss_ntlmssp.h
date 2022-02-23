/* Copyright 2013 Simo Sorce <simo@samba.org>, see COPYING for license */

#ifndef _GSS_NTLMSSP_H_
#define _GSS_NTLMSSP_H_

#include "ntlm.h"
#include "crypto.h"
#include "gssapi_ntlmssp.h"
#include "debug.h"

#define DEF_NB_DOMAIN "WORKSTATION"
#define MAX_CHALRESP_LIFETIME 36 * 60 * 60 /* 36 hours in seconds */

#define NTLMSSP_DEFAULT_CLIENT_FLAGS ( \
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                NTLMSSP_NEGOTIATE_128 | \
                NTLMSSP_NEGOTIATE_56 | \
                NTLMSSP_NEGOTIATE_NTLM | \
                NTLMSSP_REQUEST_TARGET | \
                NTLMSSP_NEGOTIATE_OEM | \
                NTLMSSP_NEGOTIATE_UNICODE | \
                NTLMSSP_NEGOTIATE_VERSION)

#define NTLMSSP_DEFAULT_SERVER_FLAGS ( \
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                NTLMSSP_NEGOTIATE_56 | \
                NTLMSSP_NEGOTIATE_KEY_EXCH | \
                NTLMSSP_NEGOTIATE_128 | \
                NTLMSSP_NEGOTIATE_VERSION | \
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

struct gssntlm_name_attribute {
    char *attr_name; /* NULL indicates array termination */
    gss_buffer_desc attr_value;
};

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

    struct gssntlm_name_attribute *attrs; /* Array of name attributes */
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
            char *keyfile;
        } server;
        struct {
            struct gssntlm_name user;
            bool creds_in_cache;
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

    struct ntlm_key exported_session_key;
    struct ntlm_signseal_state crypto_state;

    uint32_t int_flags;
    time_t expiration_time;

    void *external_context;
};

#define set_GSSERRS(min, maj) \
    (void)DEBUG_GSS_ERRORS((retmaj = (maj)), (retmin = (min)))
#define set_GSSERR(min) set_GSSERRS((min), GSS_S_FAILURE)

static inline uint32_t gssntlmssp_ret_err(uint32_t *s, uint32_t n, uint32_t j)
{
    if (!s) return GSS_S_CALL_INACCESSIBLE_WRITE;
    *s = n;
    return j;
}
#define GSSERR() gssntlmssp_ret_err(minor_status, retmin, retmaj)
#define GSSERRS(min, maj) \
    DEBUG_GSS_ERRORS((retmaj = (maj)), (retmin = (min))) ? 0 : \
     gssntlmssp_ret_err(minor_status, retmin, retmaj)

/* Static const name attribute for sids list */
extern const char gssntlmssp_sids_urn[];

bool gssntlm_required_security(int security_level, struct gssntlm_ctx *ctx);

void gssntlm_set_role(struct gssntlm_ctx *ctx,
                      int desired, char *nb_domain_name);
bool gssntlm_role_is_client(struct gssntlm_ctx *ctx);
bool gssntlm_role_is_server(struct gssntlm_ctx *ctx);
bool gssntlm_role_is_domain_member(struct gssntlm_ctx *ctx);

bool gssntlm_sec_lm_ok(struct gssntlm_ctx *ctx);
bool gssntlm_sec_ntlm_ok(struct gssntlm_ctx *ctx);
bool gssntlm_sec_v2_ok(struct gssntlm_ctx *ctx);
bool gssntlm_ext_sec_ok(struct gssntlm_ctx *ctx);

uint32_t gssntlm_context_is_valid(struct gssntlm_ctx *ctx,
                                  time_t *time_now);

int gssntlm_get_lm_compatibility_level(void);

uint32_t gssntlm_mech_invoke(uint32_t *minor_status,
                             const gss_OID desired_mech,
                             const gss_OID desired_object,
                             gss_buffer_t value);

void gssntlm_int_release_name(struct gssntlm_name *name);
void gssntlm_int_release_cred(struct gssntlm_cred *cred);

size_t gssntlm_get_attrs_count(const struct gssntlm_name_attribute *attrs);
int gssntlm_copy_attrs(const struct gssntlm_name_attribute *src,
                       struct gssntlm_name_attribute **dst);
struct gssntlm_name_attribute *gssntlm_find_attr(
                                        struct gssntlm_name_attribute *attrs,
                                        const char *attr_name,
                                        size_t attr_name_len);
void gssntlm_release_attrs(struct gssntlm_name_attribute **attrs);

int gssntlm_copy_name(struct gssntlm_name *src, struct gssntlm_name *dst);
int gssntlm_copy_creds(struct gssntlm_cred *in, struct gssntlm_cred *out);

void *external_get_context(void);
void external_free_context(void *ctx);
uint32_t external_netbios_get_names(void *ctx, char **computer, char **domain);
uint32_t external_get_creds(void *ctx,
                            struct gssntlm_name *name,
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

uint32_t netbios_get_names(void *ctx, char *computer_name,
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
                                   void *external_context,
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


uint32_t gssntlm_display_status(uint32_t *minor_status,
				uint32_t status_value,
				int status_type,
				gss_OID mech_type,
				uint32_t *message_context,
				gss_buffer_t status_string);

uint32_t gssntlm_get_name_attribute(uint32_t *minor_status,
                                    gss_name_t name,
                                    gss_buffer_t attr,
                                    int *authenticated,
                                    int *complete,
                                    gss_buffer_t value,
                                    gss_buffer_t display_value,
                                    int *more);

uint32_t gssntlm_inquire_name(uint32_t *minor_status,
                              gss_name_t name,
                              int *name_is_MN,
                              gss_OID *MN_mech,
                              gss_buffer_set_t *attrs);

uint32_t gssntlm_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                           const gss_OID desired_mech,
                                           gss_buffer_t sasl_mech_name,
                                           gss_buffer_t mech_name,
                                           gss_buffer_t mech_description);

uint32_t gssntlm_inquire_mech_for_saslname(OM_uint32 *minor_status,
                                           const gss_buffer_t sasl_mech_name,
                                           gss_OID *mech_type);

uint32_t gssntlm_inquire_attrs_for_mech(uint32_t *minor_status,
                                        gss_const_OID mech_oid,
                                        gss_OID_set *mech_attrs,
                                        gss_OID_set *known_mech_attrs);

#endif /* _GSS_NTLMSSP_H_ */
