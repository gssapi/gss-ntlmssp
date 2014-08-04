/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include <errno.h>
#include "gss_ntlmssp.h"

uint32_t external_netbios_get_names(char **computer, char **domain)
{
    return ENOSYS;
}

uint32_t external_get_creds(struct gssntlm_name *name,
                            struct gssntlm_cred *cred)
{
    return ENOSYS;
}

uint32_t external_srv_auth(char *user, char *domain,
                           char *workstation, uint8_t *challenge,
                           struct ntlm_buffer *nt_chal_resp,
                           struct ntlm_buffer *lm_chal_resp,
                           struct ntlm_key *ntlmv2_key)
{
    return ENOSYS;
}
