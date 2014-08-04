/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

uint32_t winbind_get_creds(struct gssntlm_name *name,
                           struct gssntlm_cred *cred);

uint32_t winbind_srv_auth(char *user, char *domain,
                          char *workstation, uint8_t *challenge,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *ntlmv2_key);
