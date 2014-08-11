/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for license */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "gss_ntlmssp.h"

#ifdef HAVE_NLS
#include <libintl.h>
#define _(s) dgettext(PACKAGE, (s))
#else
#define _(s) (s)
#endif
#define N_(s) s

/* the order is determined by ntlm_err_code order */
static const char *err_strs[] = {
    N_("Unknown Error"),
    N_("Failed to decode data"), /* ERR_DECODE */
    N_("Failed to encode data"), /* ERR_ENCODE */
    N_("Crypto routine failure"), /* ERR_CRYPTO */
    N_("A required argument is missing"), /* ERR_NOARG */
    N_("Invalid value in argument"), /* ERR_BADARG */
    N_("Name is empty"), /* ERR_NONAME */
    N_("Not a server name"), /* ERR_NOSRVNAME */
    N_("Not a user name"), /* ERR_NOUSRNAME */
    N_("Bad LM compatibility Level"), /* ERR_BADLMLEVEL */
    N_("An impossible error occurred"), /* ERR_IMPOSSIBLE */
    N_("Invalid or incomplete context"), /* ERR_BADCTX */
    N_("Wrong context type"), /* ERR_WRONGCTX */
    N_("Wrong message type"), /* ERR_WRONGMSG */
    N_("A required Negotiate flag was no provided"), /* ERR_REQNEGFLAG */
    N_("Failed to negotiate a common set of flags"), /* ERR_FAILNEGFLAGS */
    N_("Invalid combinations of negotiate flags"), /* ERR_BADNEGFLAGS */
    N_("Not a server credential type"), /* ERR_NOSRVCRED */
    N_("Not a user redential type"), /* ERR_NOUSRCRED */
    N_("Invalid or unknown credential"), /* ERR_BADCRED */
    N_("Empty or missing token"), /* ERR_NOTOKEN */
    N_("Feature not supported"), /* ERR_NOTSUPPORTED */
    N_("Feature not available"), /* ERR_NOTAVAIL */
    N_("Name is too long"), /* ERR_NAMETOOLONG */
    N_("Required channel bingings are not available"), /* ERR_NOBINDINGS */
    N_("Server and client clocks are too far apart"), /* ERR_TIMESKEW */
    N_("Expired"), /* ERR_EXPIRED */
    N_("Invalid key length"), /* ERR_KEYLEN */
    N_("NTLM version 1 not allowed"), /* ERR_NONTLMV1 */
    N_("User not found"), /* ERR_NOUSRFOUND */
};

#define UNKNOWN_ERROR err_strs[0]

uint32_t gssntlm_display_status(uint32_t *minor_status,
                                uint32_t status_value,
                                int status_type,
                                gss_OID mech_type,
                                uint32_t *message_context,
                                gss_buffer_t status_string)
{
    uint32_t retmaj;
    uint32_t retmin;
    /* if you can't say it in ~6 lines of text we don't bother */
    char buf[512];
    int err;

    if (!status_string) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (status_type != GSS_C_MECH_CODE) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_STATUS);
    }

    *minor_status = 0;
    *message_context = 0;
    status_string->length = 0;
    status_string->value = NULL;

    if (!status_value) {
        /* There must have been *some* error. No point saying 'Success' */
        goto done;
    }

    if (status_value > ERR_BASE && status_value < ERR_LAST) {
        status_string->value = strdup(_(err_strs[status_value - ERR_BASE]));
        if (!status_string->value) {
            return GSSERRS(ENOMEM, GSS_S_FAILURE);
        }
        goto done;
    }

    /* handle both XSI and GNU specific varints of strerror_r */
    errno = 0;
#if ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE)
    /* XSI version */
    err = strerror_r(status_value, buf, 400);
    /* The XSI-compliant strerror_r() function returns 0 on success.
     * On error, a (positive) error number is returned (since glibc
     * 2.13), or -1 is returned and errno is set to indicate the
     * error (glibc versions before 2.13). */
#else
    {
        char *ret;
        ret = strerror_r(status_value, buf, 400);
        if (ret == NULL) {
            err = errno;
        } else {
            if (ret != buf) {
                memmove(buf, ret, strlen(ret) + 1);
            }
            err = 0;
        }
    }
#endif
    if (err == -1) err = errno;
    switch (err) {
    case ERANGE:
        /* Screw it, they can have a truncated version */
    case 0:
        status_string->value = strdup(buf);
        break;
    default:
        break;
    }

done:
    if (!status_string->value) {
        status_string->value = strdup(_(UNKNOWN_ERROR));
        if (!status_string->value) {
            return GSSERRS(ENOMEM, GSS_S_FAILURE);
        }
    }
    status_string->length = strlen(status_string->value);
    return GSSERRS(0, GSS_S_COMPLETE);
}
