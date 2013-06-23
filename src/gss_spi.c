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
