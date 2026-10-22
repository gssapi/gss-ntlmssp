/*
 * Copyright (C) 2026 GSS-NTLMSSP contributors, see COPYING for License
 *
 * Integration test for GSSNTLMSSP against Active Directory DC via Winbind.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

static gss_OID_desc ntlmssp_oid = {
    10,
    discard_const("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
};

static void print_gss_err(const char *msg, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_str;
    OM_uint32 min_stat;

    fprintf(stderr, "%s: maj=%u, min=%u\n", msg, maj, min);
    do {
        gss_display_status(&min_stat, maj, GSS_C_GSS_CODE, GSS_C_NO_OID,
                           &msg_ctx, &status_str);
        fprintf(stderr, "  GSS-API: %.*s\n", (int)status_str.length, (char *)status_str.value);
        gss_release_buffer(&min_stat, &status_str);
    } while (msg_ctx != 0);

    msg_ctx = 0;
    do {
        gss_display_status(&min_stat, min, GSS_C_MECH_CODE, GSS_C_NO_OID,
                           &msg_ctx, &status_str);
        fprintf(stderr, "  Mech: %.*s\n", (int)status_str.length, (char *)status_str.value);
        gss_release_buffer(&min_stat, &status_str);
    } while (msg_ctx != 0);
}

static int test_auth(const char *user, const char *password, const char *target, int expect_success)
{
    OM_uint32 maj, min;
    gss_buffer_desc name_buf;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_buffer_desc target_buf;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc pw_buf;
    gss_OID_set_desc mech_set;
    gss_cred_id_t client_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t server_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t client_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t server_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t auth_user = GSS_C_NO_NAME;
    int ret = 1;

    name_buf.value = discard_const(user);
    name_buf.length = strlen(user);
    maj = gss_import_name(&min, &name_buf, GSS_C_NT_USER_NAME, &client_name);
    if (maj != GSS_S_COMPLETE) {
        print_gss_err("gss_import_name(user) failed", maj, min);
        goto done;
    }

    target_buf.value = discard_const(target);
    target_buf.length = strlen(target);
    maj = gss_import_name(&min, &target_buf, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (maj != GSS_S_COMPLETE) {
        print_gss_err("gss_import_name(target) failed", maj, min);
        goto done;
    }

    pw_buf.value = discard_const(password);
    pw_buf.length = strlen(password);
    mech_set.count = 1;
    mech_set.elements = &ntlmssp_oid;

    maj = gss_acquire_cred_with_password(&min, client_name, &pw_buf,
                                         GSS_C_INDEFINITE, &mech_set,
                                         GSS_C_INITIATE, &client_cred,
                                         NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
        print_gss_err("gss_acquire_cred_with_password failed", maj, min);
        goto done;
    }

    maj = gss_acquire_cred(&min, target_name, GSS_C_INDEFINITE,
                           &mech_set, GSS_C_ACCEPT, &server_cred,
                           NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
        print_gss_err("gss_acquire_cred(server) failed", maj, min);
        goto done;
    }

    /* Step 1: Client NEGOTIATE (target_name is required by GSS-API) */
    maj = gss_init_sec_context(&min, client_cred, &client_ctx,
                               target_name, &ntlmssp_oid,
                               GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
                               0, GSS_C_NO_CHANNEL_BINDINGS,
                               GSS_C_NO_BUFFER, NULL, &output_token,
                               NULL, NULL);
    if (maj != GSS_S_CONTINUE_NEEDED) {
        print_gss_err("init_sec_context step 1 failed", maj, min);
        goto done;
    }

    /* Step 2: Server CHALLENGE */
    input_token = output_token;
    output_token.value = NULL;
    output_token.length = 0;
    maj = gss_accept_sec_context(&min, &server_ctx, server_cred,
                                 &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                 NULL, NULL, &output_token,
                                 NULL, NULL, NULL);
    gss_release_buffer(&min, &input_token);
    if (maj != GSS_S_CONTINUE_NEEDED) {
        print_gss_err("accept_sec_context step 1 failed", maj, min);
        goto done;
    }

    /* Step 3: Client AUTH */
    input_token = output_token;
    output_token.value = NULL;
    output_token.length = 0;
    maj = gss_init_sec_context(&min, client_cred, &client_ctx,
                               target_name, &ntlmssp_oid,
                               GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
                               0, GSS_C_NO_CHANNEL_BINDINGS,
                               &input_token, NULL, &output_token,
                               NULL, NULL);
    gss_release_buffer(&min, &input_token);
    if (maj != GSS_S_COMPLETE) {
        print_gss_err("init_sec_context step 2 failed", maj, min);
        goto done;
    }

    /* Step 4: Server accepts AUTH (validates with winbind against AD DC) */
    input_token = output_token;
    output_token.value = NULL;
    output_token.length = 0;
    maj = gss_accept_sec_context(&min, &server_ctx, server_cred,
                                 &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                 &auth_user, NULL, &output_token,
                                 NULL, NULL, NULL);
    gss_release_buffer(&min, &input_token);
    gss_release_buffer(&min, &output_token);

    if (expect_success) {
        if (maj != GSS_S_COMPLETE) {
            print_gss_err("accept_sec_context step 2 (winbind) failed", maj, min);
            goto done;
        }

        gss_buffer_desc name_out;
        maj = gss_display_name(&min, auth_user, &name_out, NULL);
        if (maj != GSS_S_COMPLETE) {
            print_gss_err("gss_display_name failed", maj, min);
            goto done;
        }
        printf("Authenticated user: %.*s\n", (int)name_out.length, (char *)name_out.value);
        gss_release_buffer(&min, &name_out);

        /* Verify urn:gssntlmssp:sids attribute */
        const char *sids_str = "urn:gssntlmssp:sids";
        gss_buffer_desc sids_attr = { strlen(sids_str), discard_const(sids_str) };
        gss_buffer_desc sids_val = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc sids_disp = GSS_C_EMPTY_BUFFER;
        int authenticated = 0, complete = 0, more = 0;
        maj = gss_get_name_attribute(&min, auth_user, &sids_attr,
                                     &authenticated, &complete,
                                     &sids_val, &sids_disp, &more);
        if (maj == GSS_S_COMPLETE && sids_val.length > 0) {
            printf("Obtained SIDs attribute: %.*s\n", (int)sids_val.length, (char *)sids_val.value);
            if (strstr((const char *)sids_val.value, "S-1-5-") == NULL) {
                fprintf(stderr, "Error: SIDs attribute missing expected S-1-5 prefix: %.*s\n",
                        (int)sids_val.length, (char *)sids_val.value);
                gss_release_buffer(&min, &sids_val);
                gss_release_buffer(&min, &sids_disp);
                goto done;
            }
            gss_release_buffer(&min, &sids_val);
            gss_release_buffer(&min, &sids_disp);
        } else {
            print_gss_err("gss_get_name_attribute(urn:gssntlmssp:sids) failed", maj, min);
            goto done;
        }

        /* Verify wrap & unwrap (confidentiality & integrity) */
        const char *secret_msg = "Test Secret Data 1";
        gss_buffer_desc msg_in = { strlen(secret_msg), discard_const(secret_msg) };
        gss_buffer_desc wrap_token = GSS_C_EMPTY_BUFFER;
        int conf_state = 0;
        maj = gss_wrap(&min, client_ctx, 1, GSS_C_QOP_DEFAULT, &msg_in, &conf_state, &wrap_token);
        if (maj != GSS_S_COMPLETE || !conf_state) {
            print_gss_err("gss_wrap failed", maj, min);
            goto done;
        }

        gss_buffer_desc msg_out = GSS_C_EMPTY_BUFFER;
        maj = gss_unwrap(&min, server_ctx, &wrap_token, &msg_out, &conf_state, NULL);
        gss_release_buffer(&min, &wrap_token);
        if (maj != GSS_S_COMPLETE || msg_out.length != msg_in.length ||
            memcmp(msg_out.value, msg_in.value, msg_in.length) != 0) {
            print_gss_err("gss_unwrap failed", maj, min);
            gss_release_buffer(&min, &msg_out);
            goto done;
        }
        gss_release_buffer(&min, &msg_out);

        /* Verify MIC (integrity) */
        const char *mic_text = "Message MIC!";
        gss_buffer_desc mic_msg = { strlen(mic_text), discard_const(mic_text) };
        gss_buffer_desc mic_token = GSS_C_EMPTY_BUFFER;
        maj = gss_get_mic(&min, server_ctx, GSS_C_QOP_DEFAULT, &mic_msg, &mic_token);
        if (maj != GSS_S_COMPLETE) {
            print_gss_err("gss_get_mic failed", maj, min);
            goto done;
        }

        maj = gss_verify_mic(&min, client_ctx, &mic_msg, &mic_token, NULL);
        gss_release_buffer(&min, &mic_token);
        if (maj != GSS_S_COMPLETE) {
            print_gss_err("gss_verify_mic failed", maj, min);
            goto done;
        }

        ret = 0;
    } else {
        /* Expecting failure */
        if (maj == GSS_S_COMPLETE) {
            fprintf(stderr, "Authentication succeeded when failure was expected!\n");
            ret = 1;
            goto done;
        }
        printf("Authentication failed as expected with invalid credentials (maj=%u, min=%u)\n", maj, min);
        ret = 0;
    }

done:
    if (client_ctx != GSS_C_NO_CONTEXT) gss_delete_sec_context(&min, &client_ctx, GSS_C_NO_BUFFER);
    if (server_ctx != GSS_C_NO_CONTEXT) gss_delete_sec_context(&min, &server_ctx, GSS_C_NO_BUFFER);
    if (client_name != GSS_C_NO_NAME) gss_release_name(&min, &client_name);
    if (target_name != GSS_C_NO_NAME) gss_release_name(&min, &target_name);
    if (auth_user != GSS_C_NO_NAME) gss_release_name(&min, &auth_user);
    if (client_cred != GSS_C_NO_CREDENTIAL) gss_release_cred(&min, &client_cred);
    if (server_cred != GSS_C_NO_CREDENTIAL) gss_release_cred(&min, &server_cred);
    gss_release_buffer(&min, &input_token);
    gss_release_buffer(&min, &output_token);

    return ret;
}

int main(int argc, char *argv[])
{
    const char *user = (argc > 1) ? argv[1] : "TESTDOM\\testuser";
    const char *pass = (argc > 2) ? argv[2] : "TestPassw0rd123!";
    const char *target = (argc > 3) ? argv[3] : "host@addc.test.local";
    int ret;

    /* Ensure NTLM_USER_FILE is not set so GSSNTLMSSP uses winbind */
    unsetenv("NTLM_USER_FILE");

    printf("=== Test 1: Valid authentication via Winbind ===\n");
    ret = test_auth(user, pass, target, 1);
    if (ret != 0) {
        fprintf(stderr, "Test 1 FAILED\n");
        return 1;
    }
    printf("Test 1 PASSED\n\n");

    printf("=== Test 2: Invalid password rejection via Winbind ===\n");
    ret = test_auth(user, "WrongPassword999!", target, 0);
    if (ret != 0) {
        fprintf(stderr, "Test 2 FAILED\n");
        return 1;
    }
    printf("Test 2 PASSED\n\n");

    printf("=== Test 3: Invalid user rejection via Winbind ===\n");
    ret = test_auth("TESTDOM\\nonexistentuser", "TestPassw0rd123!", target, 0);
    if (ret != 0) {
        fprintf(stderr, "Test 3 FAILED\n");
        return 1;
    }
    printf("Test 3 PASSED\n\n");

    printf("All Winbind AD DC GSSNTLMSSP tests passed successfully!\n");
    return 0;
}
