/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

uint32_t winbind_get_names(char **computer, char **domain);

uint32_t winbind_get_creds(struct gssntlm_name *name,
                           struct gssntlm_cred *cred);

uint32_t winbind_cli_auth(char *user, char *domain,
                          gss_channel_bindings_t input_chan_bindings,
                          uint32_t in_flags,
                          uint32_t *neg_flags,
                          struct ntlm_buffer *nego_msg,
                          struct ntlm_buffer *chal_msg,
                          struct ntlm_buffer *auth_msg,
                          struct ntlm_key *exported_session_key);
uint32_t winbind_srv_auth(char *user, char *domain,
                          char *workstation, uint8_t *challenge,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *ntlmv2_key,
                          uint32_t *num_sids,
                          ntlm_raw_sid *sids);
