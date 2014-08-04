/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include "config.h"

#if HAVE_WBCLIENT
#include <errno.h>
#include <string.h>
#include "gss_ntlmssp.h"
#include "gss_ntlmssp_winbind.h"

#include <wbclient.h>

uint32_t winbind_get_creds(struct gssntlm_name *name,
                           struct gssntlm_cred *cred)
{
    struct wbcCredentialCacheParams params;
    struct wbcCredentialCacheInfo *result;
    struct wbcInterfaceDetails *details = NULL;
    wbcErr wbc_status;
    int ret = ENOENT;

    if (name && name->data.user.domain) {
        params.domain_name = name->data.user.domain;
    } else {
        wbc_status = wbcInterfaceDetails(&details);
        if (!WBC_ERROR_IS_OK(wbc_status)) goto done;

        params.domain_name = details->netbios_domain;
    }

    if (name && name->data.user.name) {
        params.account_name = name->data.user.name;
    } else {
        params.account_name = getenv("NTLMUSER");
        if (!params.account_name) {
            params.account_name = getenv("USER");
        }
        if (!params.account_name) goto done;
    }

    params.level = WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP;
    params.num_blobs = 0;
    params.blobs = NULL;
    wbc_status = wbcCredentialCache(&params, &result, NULL);

    if(!WBC_ERROR_IS_OK(wbc_status)) goto done;

    /* Yes, winbind seems to think it has credentials for us */
    wbcFreeMemory(result);

    cred->type = GSSNTLM_CRED_EXTERNAL;
    cred->cred.external.user.type = GSSNTLM_NAME_USER;
    cred->cred.external.user.data.user.domain = strdup(params.domain_name);
    if (!cred->cred.external.user.data.user.domain) {
        ret = ENOMEM;
        goto done;
    }
    cred->cred.external.user.data.user.name = strdup(params.account_name);
    if (!cred->cred.external.user.data.user.name) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    wbcFreeMemory(details);
    return ret;
}

uint32_t winbind_srv_auth(char *user, char *domain,
                          char *workstation, uint8_t *challenge,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *ntlmv2_key)
{
    struct wbcAuthUserParams wbc_params = { 0 };
    struct wbcAuthUserInfo *wbc_info = NULL;
    struct wbcAuthErrorInfo *wbc_err = NULL;
    wbcErr wbc_status;

    if (ntlmv2_key->length != 16) {
        return EINVAL;
    }

    wbc_params.account_name = user;
    wbc_params.domain_name = domain;
    wbc_params.workstation_name = workstation;
    wbc_params.flags = 0;
    wbc_params.parameter_control =
        WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
        WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;
    wbc_params.level = WBC_AUTH_USER_LEVEL_RESPONSE;
    memcpy(wbc_params.password.response.challenge, challenge, 8);
    wbc_params.password.response.nt_length = nt_chal_resp->length;
    wbc_params.password.response.nt_data = nt_chal_resp->data;
    wbc_params.password.response.lm_length = lm_chal_resp->length;
    wbc_params.password.response.lm_data = lm_chal_resp->data;

    wbc_status = wbcAuthenticateUserEx(&wbc_params, &wbc_info, &wbc_err);

    if (!WBC_ERROR_IS_OK(wbc_status)) {
        /* TODO: use wbcErrorString, to save error message */
        wbcFreeMemory(wbc_err);
        return EACCES;
    }

    memcpy(ntlmv2_key->data, wbc_info->user_session_key, ntlmv2_key->length);

    wbcFreeMemory(wbc_info);
    return 0;
}
#endif
