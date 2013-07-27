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

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "gss_ntlmssp.h"

static uint32_t string_split(uint32_t *retmin, char sep,
                             const char *str, size_t len,
                             char **s1, char **s2)
{
    uint32_t retmaj;
    char *r1 = NULL;
    char *r2 = NULL;
    const char *p;
    size_t l;

    p = memchr(str, sep, len);
    if (!p) return GSS_S_UNAVAILABLE;

    if (s1) {
        l = p - str;
        r1 = strndup(str, l);
        if (!r1) {
            *retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
    }
    if (s2) {
        p++;
        l = len - (p - str);
        r2 = strndup(p, l);
        if (!r2) {
            *retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
    }

    retmaj = GSS_S_COMPLETE;

done:
    if (retmaj) {
        free(r1);
        free(r2);
    } else {
        if (s1) *s1 = r1;
        if (s2) *s2 = r2;
    }
    return retmaj;
}

static uint32_t uid_to_name(uint32_t *retmin, uid_t uid, char **name)
{
    struct passwd *pw;

    pw = getpwuid(uid);
    if (pw) {
        *retmin = ENOENT;
        return GSS_S_FAILURE;
    }
    *name = strdup(pw->pw_name);
    if (!*name) {
        *retmin = ENOMEM;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

uint32_t gssntlm_import_name_by_mech(uint32_t *minor_status,
                                     gss_const_OID mech_type,
                                     gss_buffer_t input_name_buffer,
                                     gss_OID input_name_type,
                                     gss_name_t *output_name)
{
    char hostname[HOST_NAME_MAX + 1] = { 0 };
    char struid[12] = { 0 };
    uid_t uid;
    struct gssntlm_name *name = NULL;
    uint32_t retmaj = GSS_S_FAILURE;
    uint32_t retmin = 0;

    /* TODO: check mech_type == gssntlm_oid */
    if (mech_type == GSS_C_NO_OID) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    name = calloc(1, sizeof(struct gssntlm_name));
    if (!name) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (input_name_type == GSS_C_NULL_OID) {
        retmaj = GSS_S_BAD_NAMETYPE;
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_HOSTBASED_SERVICE) ||
               gss_oid_equal(input_name_type, GSS_C_NT_HOSTBASED_SERVICE_X)) {

        name->type = GSSNTLM_NAME_SERVER;

        retmaj = string_split(&retmin, '@',
                              input_name_buffer->value,
                              input_name_buffer->length,
                              NULL, &name->data.server.name);
        if ((retmaj == GSS_S_COMPLETE) ||
            (retmaj != GSS_S_UNAVAILABLE)) {
            goto done;
        }

        /* no seprator, assume only service is provided and try to source
         * the local host name */
        retmin = gethostname(hostname, HOST_NAME_MAX);
        if (retmin) {
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        name->data.server.name = strdup(hostname);
        if (!name->data.server.name) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
        }
        retmaj = GSS_S_COMPLETE;

    } else if (gss_oid_equal(input_name_type, GSS_C_NT_USER_NAME)) {

        name->type = GSSNTLM_NAME_USER;

        /* Check if in classic DOMAIN\User windows format */
        retmaj = string_split(&retmin, '\\',
                              input_name_buffer->value,
                              input_name_buffer->length,
                              &name->data.user.domain,
                              &name->data.user.name);
        if ((retmaj == GSS_S_COMPLETE) ||
            (retmaj != GSS_S_UNAVAILABLE)) {
            goto done;
        }
        /* else accept a user@domain format too */
        retmaj = string_split(&retmin, '@',
                              input_name_buffer->value,
                              input_name_buffer->length,
                              &name->data.user.name,
                              &name->data.user.domain);
        if ((retmaj == GSS_S_COMPLETE) ||
            (retmaj != GSS_S_UNAVAILABLE)) {
            goto done;
        }
        /* finally, take string as simple user name */
        name->data.user.domain = NULL;
        name->data.user.name = strndup(input_name_buffer->value,
                                       input_name_buffer->length);
        if (!name->data.user.name) {
            retmin = ENOMEM;
            retmaj = GSS_S_FAILURE;
        }
        retmaj = GSS_S_COMPLETE;
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_MACHINE_UID_NAME)) {

        name->type = GSSNTLM_NAME_USER;
        name->data.user.domain = NULL;

        uid = *(uid_t *)input_name_buffer->value;
        retmaj = uid_to_name(&retmin, uid, &name->data.user.name);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_STRING_UID_NAME)) {

        name->type = GSSNTLM_NAME_USER;
        name->data.user.domain = NULL;

        if (input_name_buffer->length > 12) {
            retmin = EINVAL;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        memcpy(struid, input_name_buffer->value, input_name_buffer->length);
        struid[11] = '\0';
        errno = 0;
        uid = strtol(struid, NULL, 10);
        if (errno) {
            retmin = errno;
            retmaj = GSS_S_FAILURE;
            goto done;
        }
        retmaj = uid_to_name(&retmin, uid, &name->data.user.name);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_ANONYMOUS)) {
        name->type = GSSNTLM_NAME_ANON;
        retmaj = GSS_S_COMPLETE;
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_EXPORT_NAME)) {
        /* TODO */
        retmaj = GSS_S_UNAVAILABLE;
    }

done:
    if (retmaj != GSS_S_COMPLETE) {
        uint32_t tmpmin;
        gssntlm_release_name(&tmpmin, (gss_name_t *)&name);
    } else {
        *output_name = (gss_name_t)name;
    }
    *minor_status = retmin;
    return retmaj;
}

uint32_t gssntlm_import_name(uint32_t *minor_status,
                             gss_buffer_t input_name_buffer,
                             gss_OID input_name_type,
                             gss_name_t *output_name)
{
    return gssntlm_import_name_by_mech(minor_status,
                                       discard_const(&gssntlm_oid),
                                       input_name_buffer,
                                       input_name_type,
                                       output_name);
}

int gssntlm_copy_name(struct gssntlm_name *src, struct gssntlm_name *dst)
{
    char *dom = NULL, *usr = NULL, *srv = NULL;
    int ret;
    dst->type = src->type;
    switch (src->type) {
    case GSSNTLM_NAME_ANON:
        break;
    case GSSNTLM_NAME_USER:
        if (src->data.user.domain) {
            dom = strdup(src->data.user.domain);
            if (!dom) {
                ret = ENOMEM;
                goto done;
            }
        }
        if (src->data.user.name) {
            usr = strdup(src->data.user.name);
            if (!usr) {
                ret = ENOMEM;
                goto done;
            }
        }
        dst->data.user.domain = dom;
        dst->data.user.name = usr;
        break;
    case GSSNTLM_NAME_SERVER:
        if (src->data.server.name) {
            srv = strdup(src->data.server.name);
            if (!srv) {
                ret = ENOMEM;
                goto done;
            }
        }
        dst->data.server.name = srv;
        break;
    }

    ret = 0;
done:
    if (ret) {
        safefree(dom);
        safefree(usr);
        safefree(srv);
    }
    return ret;
}

uint32_t gssntlm_duplicate_name(uint32_t *minor_status,
                                const gss_name_t input_name,
                                gss_name_t *dest_name)
{
    struct gssntlm_name *in;
    struct gssntlm_name *out;
    uint32_t retmin;

    *minor_status = 0;

    if (input_name == GSS_C_NO_NAME || dest_name == NULL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    in = (struct gssntlm_name *)input_name;

    out = calloc(1, sizeof(struct gssntlm_name));
    if (!out) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    retmin = gssntlm_copy_name(in, out);

    *minor_status = retmin;
    if (retmin) return GSS_S_FAILURE;

    *dest_name = (gss_name_t)out;
    return GSS_S_COMPLETE;
}

void gssntlm_int_release_name(struct gssntlm_name *name)
{
    if (!name) return;

    switch (name->type) {
    case GSSNTLM_NAME_ANON:
        break;
    case GSSNTLM_NAME_USER:
        safefree(name->data.user.domain);
        safefree(name->data.user.name);
        break;
    case GSSNTLM_NAME_SERVER:
        safefree(name->data.server.name);
        break;
    }
}

uint32_t gssntlm_release_name(uint32_t *minor_status,
                              gss_name_t *input_name)
{
    if (!input_name) return GSS_S_CALL_INACCESSIBLE_READ;

    gssntlm_int_release_name((struct gssntlm_name *)*input_name);

    *input_name = GSS_C_NO_NAME;
    return GSS_S_COMPLETE;
}
