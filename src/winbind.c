/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for License */

#include "config.h"

#include <errno.h>
#include <string.h>
#include "gss_ntlmssp.h"
#include "gss_ntlmssp_winbind.h"

#include <wbclient.h>

uint32_t winbind_get_names(char **computer, char **domain)
{
    struct wbcInterfaceDetails *details = NULL;
    wbcErr wbc_status;
    int ret = ERR_NOTAVAIL;

    wbc_status = wbcInterfaceDetails(&details);
    if (!WBC_ERROR_IS_OK(wbc_status)) goto done;

    if (computer &&
        details->netbios_name &&
        (details->netbios_name[0] != 0)) {
        *computer = strdup(details->netbios_name);
        if (!*computer) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (domain &&
        details->netbios_domain &&
        (details->netbios_domain[0] != 0)) {
        *domain = strdup(details->netbios_domain);
        if (!*domain) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret) {
        if (computer) safefree(*computer);
    }
    wbcFreeMemory(details);
    return ret;
}

uint32_t winbind_get_creds(struct gssntlm_name *name,
                           struct gssntlm_cred *cred)
{
    struct wbcCredentialCacheParams params;
    struct wbcCredentialCacheInfo *result;
    struct wbcInterfaceDetails *details = NULL;
    wbcErr wbc_status;
    int ret = ERR_NOTAVAIL;

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

uint32_t winbind_cli_auth(char *user, char *domain,
                          gss_channel_bindings_t input_chan_bindings,
                          uint32_t in_flags,
                          uint32_t *neg_flags,
                          struct ntlm_buffer *nego_msg,
                          struct ntlm_buffer *chal_msg,
                          struct ntlm_buffer *auth_msg,
                          struct ntlm_key *exported_session_key)
{
    /* Get responses and session key from winbind */
    struct wbcCredentialCacheParams params;
    struct wbcCredentialCacheInfo *result = NULL;
    struct wbcNamedBlob *sesskey_blob = NULL;
    struct wbcNamedBlob *auth_blob = NULL;
    struct wire_auth_msg *w_auth_msg;
    struct wire_chal_msg *w_chal_msg;
    wbcErr wbc_status;
    int ret;
    int i;

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
        /* Winbind doesn't support this (yet). We'd want to pass our
         * own client_target_info in with the request. */
        ret = ERR_NOTSUPPORTED;
        goto done;
    }

    params.account_name = user;
    params.domain_name= domain;
    params.level = WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP;
    params.num_blobs = 0;
    params.blobs = NULL;

    wbc_status = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
                                 "challenge_blob", 0,
                                 chal_msg->data, chal_msg->length);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        ret = ENOMEM;
        goto done;
    }
    /* If we've masked out flags in in_flags, don't let
     * winbind see them in the challenge */
    w_chal_msg = (struct wire_chal_msg *)params.blobs[0].blob.data;
    w_chal_msg->neg_flags = htole32(in_flags);

    /* Put this in second.
     * https://bugzilla.samba.org/show_bug.cgi?id=10692 */
    if (nego_msg->length) {
        wbc_status = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
                                     "initial_blob", 0,
                                     nego_msg->data, nego_msg->length);
        if (!WBC_ERROR_IS_OK(wbc_status)) {
            ret = ENOMEM;
            goto done;
        }
    }

    wbc_status = wbcCredentialCache(&params, &result, NULL);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        ret = ERR_NOTAVAIL;
        goto done;
    }
    for (i = 0; i < result->num_blobs; i++) {
        if (strcmp(result->blobs[i].name, "auth_blob") == 0) {
            auth_blob = &result->blobs[i];
        } else if (strcmp(result->blobs[i].name, "session_key") == 0) {
            sesskey_blob = &result->blobs[i];
        }
    }

    if (!auth_blob || auth_blob->blob.length < sizeof(*auth_msg) ||
        !sesskey_blob || sesskey_blob->blob.length != 16 ) {
        ret = ERR_KEYLEN;
        goto done;
    }
    /* We need to 'correct' the flags in the auth message that
     * winbind generates.  In datagram mode they do matter.
     * Winbind leaves out the DATAGRAM and SEAL flags, amongst
     * others. Thankfully winbind also doesn't support MIC so
     * we can tamper as much as we like... */
    w_auth_msg = (struct wire_auth_msg *)auth_blob->blob.data;
    *neg_flags |= in_flags;
    w_auth_msg->neg_flags = htole32(*neg_flags);

    auth_msg->length = auth_blob->blob.length;
    auth_msg->data = auth_blob->blob.data;
    auth_blob->blob.data = NULL;

    exported_session_key->length = sesskey_blob->blob.length;
    memcpy(exported_session_key->data, sesskey_blob->blob.data,
           sesskey_blob->blob.length);

    ret = 0;

done:
    wbcFreeMemory(params.blobs);
    wbcFreeMemory(result);
    return ret;
}

uint32_t winbind_srv_auth(char *user, char *domain,
                          char *workstation, uint8_t *challenge,
                          struct ntlm_buffer *nt_chal_resp,
                          struct ntlm_buffer *lm_chal_resp,
                          struct ntlm_key *ntlmv2_key,
                          uint32_t *num_sids,
                          ntlm_raw_sid *sids)
{
    struct wbcAuthUserParams wbc_params = { 0 };
    struct wbcAuthUserInfo *wbc_info = NULL;
    struct wbcAuthErrorInfo *wbc_err = NULL;
    wbcErr wbc_status;

    if (ntlmv2_key->length != 16) {
        return ERR_KEYLEN;
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

    // num_sids is INOUT: IN - maximum number of sids to be returned
    //                    OUT - actual number of sids
    if (wbc_info->num_sids < *num_sids) {
        *num_sids = wbc_info->num_sids;
    }
    for (uint32_t i = 0; i < *num_sids; i++) {
        memcpy(&sids[i], &wbc_info->sids[i].sid, sizeof(ntlm_raw_sid));
    }

    wbcFreeMemory(wbc_info);
    return 0;
}
