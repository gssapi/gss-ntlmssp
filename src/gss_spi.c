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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "gss_ntlmssp.h"

OM_uint32 gss_init_sec_context(OM_uint32 *minor_status,
                               gss_cred_id_t claimant_cred_handle,
                               gss_ctx_id_t *context_handle,
                               gss_name_t target_name,
                               gss_OID mech_type,
                               OM_uint32 req_flags,
                               OM_uint32 time_req,
                               gss_channel_bindings_t input_chan_bindings,
                               gss_buffer_t input_token,
                               gss_OID *actual_mech_type,
                               gss_buffer_t output_token,
                               OM_uint32 *ret_flags,
                               OM_uint32 *time_rec)
{
    return gssntlm_init_sec_context(minor_status,
                                    claimant_cred_handle,
                                    context_handle,
                                    target_name,
                                    mech_type,
                                    req_flags,
                                    time_req,
                                    input_chan_bindings,
                                    input_token,
                                    actual_mech_type,
                                    output_token,
                                    ret_flags,
                                    time_rec);
}

OM_uint32 gss_delete_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_buffer_t output_token)
{
    return gssntlm_delete_sec_context(minor_status,
                                      context_handle,
                                      output_token);
}

OM_uint32 gss_acquire_cred_from(OM_uint32 *minor_status,
                                gss_name_t desired_name,
                                OM_uint32 time_req,
                                gss_OID_set desired_mechs,
                                gss_cred_usage_t cred_usage,
                                gss_const_key_value_set_t cred_store,
                                gss_cred_id_t *output_cred_handle,
                                gss_OID_set *actual_mechs,
                                OM_uint32 *time_rec)
{
    return gssntlm_acquire_cred_from(minor_status,
                                     desired_name,
                                     time_req,
                                     desired_mechs,
                                     cred_usage,
                                     cred_store,
                                     output_cred_handle,
                                     actual_mechs,
                                     time_rec);
}

OM_uint32 gss_acquire_cred(OM_uint32 *minor_status,
                           gss_name_t desired_name,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec)
{
    return gssntlm_acquire_cred(minor_status,
                                desired_name,
                                time_req,
                                desired_mechs,
                                cred_usage,
                                output_cred_handle,
                                actual_mechs,
                                time_rec);
}

OM_uint32 gssspi_acquire_cred_with_password(OM_uint32 *minor_status,
                                            gss_name_t desired_name,
                                            gss_buffer_t password,
                                            OM_uint32 time_req,
                                            gss_OID_set desired_mechs,
                                            gss_cred_usage_t cred_usage,
                                            gss_cred_id_t *output_cred_handle,
                                            gss_OID_set *actual_mechs,
                                            OM_uint32 *time_rec)
{
    return gssntlm_acquire_cred_with_password(minor_status,
                                              desired_name,
                                              password,
                                              time_req,
                                              desired_mechs,
                                              cred_usage,
                                              output_cred_handle,
                                              actual_mechs,
                                              time_rec);
}

OM_uint32 gss_release_cred(OM_uint32 *minor_status,
                           gss_cred_id_t *cred_handle)
{
    return gssntlm_release_cred(minor_status, cred_handle);
}

OM_uint32 gss_import_name(OM_uint32 *minor_status,
                          gss_buffer_t input_name_buffer,
                          gss_OID input_name_type,
                          gss_name_t *output_name)
{
    return gssntlm_import_name(minor_status,
                               input_name_buffer,
                               input_name_type,
                               output_name);
}

OM_uint32 gssspi_import_name_by_mech(OM_uint32 *minor_status,
                                     gss_OID mech_type,
                                     gss_buffer_t input_name_buffer,
                                     gss_OID input_name_type,
                                     gss_name_t *output_name)
{
    return gssntlm_import_name(minor_status,
                               input_name_buffer,
                               input_name_type,
                               output_name);
}

OM_uint32 gss_duplicate_name(OM_uint32 *minor_status,
                            const gss_name_t input_name,
                            gss_name_t *dest_name)
{
    return gssntlm_duplicate_name(minor_status,
                                  input_name, dest_name);
}

OM_uint32 gss_release_name(OM_uint32 *minor_status,
                           gss_name_t *input_name)
{
    return gssntlm_release_name(minor_status,
                                input_name);
}

OM_uint32 gss_context_time(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle,
                           OM_uint32 *time_rec)
{
    return gssntlm_context_time(minor_status, context_handle, time_rec);
}

OM_uint32 gss_accept_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_cred_id_t acceptor_cred_handle,
                                 gss_buffer_t input_token_buffer,
                                 gss_channel_bindings_t input_chan_bindings,
                                 gss_name_t *src_name,
                                 gss_OID *mech_type,
                                 gss_buffer_t output_token,
                                 OM_uint32 *ret_flags,
                                 OM_uint32 *time_rec,
                                 gss_cred_id_t *delegated_cred_handle)
{
    return gssntlm_accept_sec_context(minor_status,
                                      context_handle,
                                      acceptor_cred_handle,
                                      input_token_buffer,
                                      input_chan_bindings,
                                      src_name,
                                      mech_type,
                                      output_token,
                                      ret_flags,
                                      time_rec,
                                      delegated_cred_handle);
}

OM_uint32 gss_get_mic(OM_uint32 *minor_status,
                      gss_ctx_id_t context_handle,
                      gss_qop_t qop_req,
                      gss_buffer_t message_buffer,
                      gss_buffer_t message_token)
{
    return gssntlm_get_mic(minor_status,
                           context_handle,
                           qop_req,
                           message_buffer,
                           message_token);
}


OM_uint32 gss_verify_mic(OM_uint32 *minor_status,
                         gss_ctx_id_t context_handle,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token,
                         gss_qop_t *qop_state)
{
    return gssntlm_verify_mic(minor_status,
                              context_handle,
                              message_buffer,
                              message_token,
                              qop_state);
}

OM_uint32 gss_wrap(OM_uint32 *minor_status,
                   gss_ctx_id_t context_handle,
                   int conf_req_flag,
                   gss_qop_t qop_req,
                   gss_buffer_t input_message_buffer,
                   int *conf_state,
                   gss_buffer_t output_message_buffer)
{
    return gssntlm_wrap(minor_status,
                        context_handle,
                        conf_req_flag,
                        qop_req,
                        input_message_buffer,
                        conf_state,
                        output_message_buffer);
}

OM_uint32 gss_unwrap(OM_uint32 *minor_status,
                     gss_ctx_id_t context_handle,
                     gss_buffer_t input_message_buffer,
                     gss_buffer_t output_message_buffer,
                     int *conf_state,
                     gss_qop_t *qop_state)
{
    return gssntlm_unwrap(minor_status,
                          context_handle,
                          input_message_buffer,
                          output_message_buffer,
                          conf_state,
                          qop_state);
}

OM_uint32 gss_inquire_context(OM_uint32 *minor_status,
                              gss_ctx_id_t context_handle,
                              gss_name_t *src_name,
                              gss_name_t *targ_name,
                              OM_uint32 *lifetime_rec,
                              gss_OID *mech_type,
                              OM_uint32 *ctx_flags,
                              int *locally_initiated,
                              int *open)
{
    return gssntlm_inquire_context(minor_status,
                                   context_handle,
                                   src_name,
                                   targ_name,
                                   lifetime_rec,
                                   mech_type,
                                   ctx_flags,
                                   locally_initiated,
                                   open);
}

OM_uint32 gss_display_name(OM_uint32 *minor_status,
                           gss_name_t input_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type)
{
    return gssntlm_display_name(minor_status,
                                input_name,
                                output_name_buffer,
                                output_name_type);
}

OM_uint32 gss_localname(OM_uint32 *minor_status,
	                const gss_name_t name,
	                gss_const_OID mech_type,
	                gss_buffer_t localname)
{
    return gssntlm_localname(minor_status,
                             name,
                             mech_type,
                             localname);
}

OM_uint32 gss_set_sec_context_option(OM_uint32 *minor_status,
                                     gss_ctx_id_t *context_handle,
                                     const gss_OID desired_object,
                                     const gss_buffer_t value)
{
    return gssntlm_set_sec_context_option(minor_status,
                                          context_handle,
                                          desired_object,
                                          value);
}

OM_uint32 gss_inquire_sec_context_by_oid(OM_uint32 *minor_status,
	                                 const gss_ctx_id_t context_handle,
	                                 const gss_OID desired_object,
	                                 gss_buffer_set_t *data_set)
{
    return gssntlm_inquire_sec_context_by_oid(minor_status,
                                              context_handle,
                                              desired_object,
                                              data_set);
}

OM_uint32 gss_inquire_cred(OM_uint32 *minor_status,
                           gss_cred_id_t cred_handle,
                           gss_name_t *name,
                           OM_uint32 *lifetime,
                           gss_cred_usage_t *cred_usage,
                           gss_OID_set *mechanisms)
{
    return gssntlm_inquire_cred(minor_status,
                                cred_handle,
                                name,
                                lifetime,
                                cred_usage,
                                mechanisms);
}

OM_uint32 gss_inquire_cred_by_mech(OM_uint32 *minor_status,
                                   gss_cred_id_t cred_handle,
                                   gss_OID mech_type,
                                   gss_name_t *name,
                                   OM_uint32 *initiator_lifetime,
                                   OM_uint32 *acceptor_lifetime,
                                   gss_cred_usage_t *cred_usage)
{
    return gssntlm_inquire_cred_by_mech(minor_status,
                                        cred_handle,
                                        mech_type,
                                        name,
                                        initiator_lifetime,
                                        acceptor_lifetime,
                                        cred_usage);
}

OM_uint32 gss_export_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_buffer_t interprocess_token)
{
    return gssntlm_export_sec_context(minor_status,
                                      context_handle,
                                      interprocess_token);
}

OM_uint32 gss_import_sec_context(OM_uint32 *minor_status,
                                 gss_buffer_t interprocess_token,
                                 gss_ctx_id_t *context_handle)
{
    return gssntlm_import_sec_context(minor_status,
                                      interprocess_token,
                                      context_handle);
}

OM_uint32 gss_export_cred(OM_uint32 *minor_status,
                          gss_cred_id_t cred_handle,
                          gss_buffer_t token)
{
    return gssntlm_export_cred(minor_status, cred_handle, token);
}

OM_uint32 gss_import_cred(OM_uint32 *minor_status,
                          gss_buffer_t token,
                          gss_cred_id_t *cred_handle)
{
    return gssntlm_import_cred(minor_status, token, cred_handle);
}
