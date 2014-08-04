/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include "config.h"
#include <errno.h>
#include "gss_ntlmssp.h"

#if HAVE_WBCLIENT
#include "gss_ntlmssp_winbind.h"
#endif

uint32_t external_netbios_get_names(char **computer, char **domain)
{
#if HAVE_WBCLIENT
    return winbind_get_names(computer, domain);
#else
    return ENOSYS;
#endif
}

uint32_t external_get_creds(struct gssntlm_name *name,
                            struct gssntlm_cred *cred)
{
#if HAVE_WBCLIENT
    return winbind_get_creds(name, cred);
#else
    return ENOSYS;
#endif
}

uint32_t external_cli_auth(char *user, char *domain,
                           gss_channel_bindings_t input_chan_bindings,
                           uint32_t in_flags,
                           uint32_t *neg_flags,
                           struct ntlm_buffer *nego_msg,
                           struct ntlm_buffer *chal_msg,
                           struct ntlm_buffer *auth_msg,
                           struct ntlm_key *exported_session_key)
{
#if HAVE_WBCLIENT
    return winbind_cli_auth(user, domain, input_chan_bindings,
                            in_flags, neg_flags,
                            nego_msg, chal_msg, auth_msg,
                            exported_session_key);
#else
    return ENOSYS;
#endif
}

uint32_t external_srv_auth(char *user, char *domain,
                           char *workstation, uint8_t *challenge,
                           struct ntlm_buffer *nt_chal_resp,
                           struct ntlm_buffer *lm_chal_resp,
                           struct ntlm_key *ntlmv2_key)
{
#if HAVE_WBCLIENT
    return winbind_srv_auth(user, domain, workstation, challenge,
                            nt_chal_resp, lm_chal_resp, ntlmv2_key);
#else
    return ENOSYS;
#endif
}
