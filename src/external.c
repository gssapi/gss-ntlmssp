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
