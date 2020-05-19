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

#define _GNU_SOURCE

#include <ctype.h>
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

static uint32_t string_split(uint32_t *minor_status, char sep,
                             const char *str, size_t len,
                             char **s1, char **s2)
{
    uint32_t retmaj;
    uint32_t retmin;
    char *r1 = NULL;
    char *r2 = NULL;
    const char *p;
    size_t l;

    p = memchr(str, sep, len);
    if (!p) return GSSERRS(0, GSS_S_UNAVAILABLE);

    if (s1) {
        l = p - str;
        r1 = strndup(str, l);
        if (!r1) {
            set_GSSERR(ENOMEM);
            goto done;
        }
    }
    if (s2) {
        p++;
        l = len - (p - str);
        r2 = strndup(p, l);
        if (!r2) {
            set_GSSERR(ENOMEM);
            goto done;
        }
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj) {
        free(r1);
        free(r2);
    } else {
        if (s1) *s1 = r1;
        if (s2) *s2 = r2;
    }
    return GSSERR();
}

#define MAX_NAME_LEN 1024
static uint32_t get_enterprise_name(uint32_t *minor_status,
                                    const char *str, size_t len,
                                    char **username)
{
    uint32_t retmaj;
    uint32_t retmin;
    char *buf;
    char *e;

    if (len > MAX_NAME_LEN) {
        return GSSERRS(ERR_NAMETOOLONG, GSS_S_BAD_NAME);
    }
    buf = alloca(len + 1);

    memcpy(buf, str, len);
    buf[len] = '\0';

    e = strstr(buf, "\\@");
    if (e) {
        /* remove escape */
        memmove(e, e + 1, len - (e - buf));
    } else {
        /* check if domain part contains dot */
        e = strchr(buf, '@');
        if (e) {
            e = strchr(e, '.');
        }
    }
    if (!e) return GSSERRS(0, GSS_S_UNAVAILABLE);

    *username = strdup(buf);
    if (NULL == *username) {
        set_GSSERR(ENOMEM);
        goto done;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

static uint32_t uid_to_name(uint32_t *minor_status, uid_t uid, char **name)
{
    uint32_t retmaj;
    uint32_t retmin;
    struct passwd *pw;

    pw = getpwuid(uid);
    if (pw) {
        return GSSERRS(ERR_NOUSRFOUND, GSS_S_FAILURE);
    }
    *name = strdup(pw->pw_name);
    if (!*name) {
        set_GSSERR(ENOMEM);
        goto done;
    }
    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
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
    uint32_t retmaj;
    uint32_t retmin;

    /* TODO: check mech_type == gssntlm_oid */
    if (mech_type == GSS_C_NO_OID) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    } else if (!gss_oid_equal(mech_type, &gssntlm_oid)) {
        return GSSERRS(ERR_BADARG, GSS_S_BAD_MECH);
    }

    name = calloc(1, sizeof(struct gssntlm_name));
    if (!name) {
        set_GSSERR(ENOMEM);
        goto done;
    }

    /* treat null OID like NT_USER_NAME */
    if (input_name_type == GSS_C_NULL_OID) {
        input_name_type = GSS_C_NT_USER_NAME;
    }

    if (gss_oid_equal(input_name_type, GSS_C_NT_HOSTBASED_SERVICE) ||
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
            set_GSSERR(retmin);
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        name->data.server.name = strdup(hostname);
        if (!name->data.server.name) {
            set_GSSERR(ENOMEM);
        }
        set_GSSERRS(0, GSS_S_COMPLETE);

    } else if (gss_oid_equal(input_name_type, GSS_C_NT_USER_NAME)) {

        name->type = GSSNTLM_NAME_USER;
        name->data.user.domain = NULL;

        /* Check if enterprise name first */
        retmaj = get_enterprise_name(&retmin,
                                     input_name_buffer->value,
                                     input_name_buffer->length,
                                     &name->data.user.name);
        if ((retmaj == GSS_S_COMPLETE) ||
            (retmaj != GSS_S_UNAVAILABLE)) {
            goto done;
        }
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
        name->data.user.name = strndup(input_name_buffer->value,
                                       input_name_buffer->length);
        if (!name->data.user.name) {
            set_GSSERR(ENOMEM);
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
            set_GSSERR(ERR_BADARG);
            goto done;
        }
        memcpy(struid, input_name_buffer->value, input_name_buffer->length);
        struid[11] = '\0';
        errno = 0;
        uid = strtol(struid, NULL, 10);
        if (errno) {
            set_GSSERR(ERR_BADARG);
            goto done;
        }
        retmaj = uid_to_name(&retmin, uid, &name->data.user.name);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_ANONYMOUS)) {
        name->type = GSSNTLM_NAME_ANON;
        set_GSSERRS(0, GSS_S_COMPLETE);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_EXPORT_NAME)) {
        /* TODO */
        set_GSSERRS(ERR_NOTSUPPORTED, GSS_S_BAD_NAMETYPE);
    } else {
        set_GSSERRS(ERR_BADARG, GSS_S_BAD_NAMETYPE);
    }

done:
    if (retmaj != GSS_S_COMPLETE) {
        uint32_t tmpmin;
        gssntlm_release_name(&tmpmin, (gss_name_t *)&name);
    } else {
        *output_name = (gss_name_t)name;
    }
    return GSSERR();
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
    case GSSNTLM_NAME_NULL:
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
    uint32_t retmaj;

    if (input_name == GSS_C_NO_NAME || dest_name == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    in = (struct gssntlm_name *)input_name;

    if (in->type == GSSNTLM_NAME_NULL) {
        *dest_name = GSS_C_NO_NAME;
        return GSSERRS(0, GSS_S_COMPLETE);
    }

    out = calloc(1, sizeof(struct gssntlm_name));
    if (!out) {
        set_GSSERR(ENOMEM);
        goto done;
    }

    retmin = gssntlm_copy_name(in, out);
    if (retmin) {
        set_GSSERR(retmin);
        goto done;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj) {
        safefree(out);
    }
    *dest_name = (gss_name_t)out;
    return GSSERR();
}

void gssntlm_int_release_name(struct gssntlm_name *name)
{
    if (!name) return;

    switch (name->type) {
    case GSSNTLM_NAME_NULL:
        return;
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
    name->type = GSSNTLM_NAME_NULL;
}

uint32_t gssntlm_release_name(uint32_t *minor_status,
                              gss_name_t *input_name)
{
    uint32_t retmaj;
    uint32_t retmin;

    if (!input_name) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    gssntlm_int_release_name((struct gssntlm_name *)*input_name);

    safefree(*input_name);
    return GSSERRS(0, GSS_S_COMPLETE);
}

uint32_t gssntlm_display_name(uint32_t *minor_status,
                              gss_name_t input_name,
                              gss_buffer_t output_name_buffer,
                              gss_OID *output_name_type)
{
    struct gssntlm_name *in;
    gss_buffer_t out;
    uint32_t retmaj;
    uint32_t retmin;
    int ret;

    if (input_name == GSS_C_NO_NAME || output_name_buffer == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    in = (struct gssntlm_name *)input_name;
    out = output_name_buffer;

    switch (in->type) {
    case GSSNTLM_NAME_NULL:
        return GSSERRS(ERR_BADARG, GSS_S_BAD_NAME);
    case GSSNTLM_NAME_ANON:
        out->value = strdup("NT AUTHORITY\\ANONYMOUS LOGON");
        if (!out->value) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        out->length = strlen(out->value) + 1;
        if (output_name_type) {
            *output_name_type = GSS_C_NT_ANONYMOUS;
        }
        break;
    case GSSNTLM_NAME_USER:
        if (in->data.user.domain) {
            ret = asprintf((char **)&out->value, "%s\\%s",
                           in->data.user.domain, in->data.user.name);
            if (ret == -1) {
                out->value = NULL;
            }
        } else {
            out->value = strdup(in->data.user.name);
        }
        if (!out->value) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        out->length = strlen(out->value) + 1;
        if (output_name_type) {
            *output_name_type = GSS_C_NT_USER_NAME;
        }
        break;
    case GSSNTLM_NAME_SERVER:
        out->value = strdup(in->data.server.name);
        if (!out->value) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        out->length = strlen(out->value) + 1;
        if (output_name_type) {
            *output_name_type = GSS_C_NT_HOSTBASED_SERVICE;
        }
        break;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    return GSSERR();
}

#define PWBUFLEN 1024

uint32_t gssntlm_localname(uint32_t *minor_status,
	                   const gss_name_t name,
	                   gss_const_OID mech_type,
	                   gss_buffer_t localname)
{
    struct gssntlm_name *in;
    char *uname = NULL;
    char pwbuf[PWBUFLEN];
    struct passwd pw, *res;
    uint32_t retmaj;
    uint32_t retmin;
    int ret;

    in = (struct gssntlm_name *)name;
    if (in->type != GSSNTLM_NAME_USER) {
        set_GSSERRS(ERR_BADARG, GSS_S_BAD_NAME);
        goto done;
    }

    /* TODO: hook up with winbindd/sssd for name resolution ? */

    if (in->data.user.domain) {
        ret = asprintf(&uname, "%s\\%s",
                       in->data.user.domain, in->data.user.name);
        if (ret == -1) {
            set_GSSERR(ENOMEM);
            goto done;
        }
        ret = getpwnam_r(uname, &pw, pwbuf, PWBUFLEN, &res);
        if (ret) {
            set_GSSERR(ret);
            goto done;
        }
        safefree(uname);
        if (res) {
            uname = strdup(res->pw_name);
        }
    }
    if (uname == NULL) {
        ret = getpwnam_r(in->data.user.name, &pw, pwbuf, PWBUFLEN, &res);
        if (ret != 0 || res == NULL) {
            set_GSSERR(ret);
            goto done;
        }
        uname = strdup(res->pw_name);
    }
    if (!uname) {
        set_GSSERR(ENOMEM);
        goto done;
    }

    set_GSSERRS(0, GSS_S_COMPLETE);

done:
    if (retmaj) {
        safefree(uname);
    } else {
        localname->value = uname;
        localname->length = strlen(uname) + 1;
    }
    return GSSERR();
}

uint32_t netbios_get_names(char *computer_name,
                           char **netbios_host, char **netbios_domain)
{
    char *nb_computer_name = NULL;
    char *nb_domain_name = NULL;
    char *env_name;
    uint32_t ret;

    env_name = getenv("NETBIOS_COMPUTER_NAME");
    if (env_name) {
        nb_computer_name = strdup(env_name);
        if (!nb_computer_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    env_name = getenv("NETBIOS_DOMAIN_NAME");
    if (env_name) {
        nb_domain_name = strdup(env_name);
        if (!nb_domain_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (!nb_computer_name || !nb_domain_name) {
        /* fetch only mising ones */
        ret = external_netbios_get_names(
                    nb_computer_name ? NULL : &nb_computer_name,
                    nb_domain_name ? NULL : &nb_domain_name);
        if ((ret != 0) &&
            (ret != ENOENT) &&
            (ret != ERR_NOTAVAIL)) {
            goto done;
        }
    }

    if (!nb_computer_name) {
        char *p;
        p = strchr(computer_name, '.');
        if (p) {
            nb_computer_name = strndup(computer_name, p - computer_name);
        } else {
            nb_computer_name = strdup(computer_name);
        }
        for (p = nb_computer_name; p && *p; p++) {
            /* Can only be ASCII, so toupper is safe */
            *p = toupper(*p);
        }
        if (!nb_computer_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (!nb_domain_name) {
        nb_domain_name = strdup(DEF_NB_DOMAIN);
        if (!nb_domain_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret) {
        safefree(nb_computer_name);
        safefree(nb_domain_name);
    }

    *netbios_domain = nb_domain_name;
    *netbios_host = nb_computer_name;
    return ret;
}

uint32_t gssntlm_inquire_name(uint32_t *minor_status,
                              gss_name_t name,
                              int *name_is_MN,
                              gss_OID *MN_mech,
                              gss_buffer_set_t *attrs)
{
    return GSS_S_UNAVAILABLE;
}

/* RFC5801 Extensions */

#define GS2_NTLM_SASL_NAME        "GS2-NTLM"
#define GS2_NTLM_SASL_NAME_LEN    (sizeof(GS2_NTLM_SASL_NAME) - 1)

uint32_t gssntlm_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                           const gss_OID desired_mech,
                                           gss_buffer_t sasl_mech_name,
                                           gss_buffer_t mech_name,
                                           gss_buffer_t mech_description)
{
    if (desired_mech && !gss_oid_equal(desired_mech, &gssntlm_oid)) {
        *minor_status = ENOENT;
        return GSS_S_BAD_MECH;
    }

    sasl_mech_name->value = NULL;
    mech_name->value = NULL;
    mech_description->value = NULL;

    *minor_status = ENOMEM;

    sasl_mech_name->value = strdup(GS2_NTLM_SASL_NAME);
    if (sasl_mech_name->value == NULL) {
        goto done;
    }
    sasl_mech_name->length = strlen(sasl_mech_name->value);

    mech_name->value = strdup("NTLM");
    if (mech_name->value == NULL) {
        goto done;
    }
    mech_name->length = strlen(mech_name->value);

    mech_description->value = strdup("NTLM Mechanism");
    if (mech_name->value == NULL) {
        goto done;
    }
    mech_description->length = strlen(mech_description->value);

    *minor_status = 0;

done:
    if (*minor_status != 0) {
        free(sasl_mech_name->value);
        free(mech_name->value);
        free(mech_description->value);
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

uint32_t gssntlm_inquire_mech_for_saslname(OM_uint32 *minor_status,
                                           const gss_buffer_t sasl_mech_name,
                                           gss_OID *mech_type)
{
    if (sasl_mech_name->length == GS2_NTLM_SASL_NAME_LEN &&
        memcmp(sasl_mech_name->value,
               GS2_NTLM_SASL_NAME, GS2_NTLM_SASL_NAME_LEN) == 0) {
        if (mech_type != NULL) {
            *mech_type = discard_const(&gssntlm_oid);
        }
        *minor_status = 0;
        return GSS_S_COMPLETE;
    }

    *minor_status = ENOENT;
    return GSS_S_BAD_MECH;

}

static uint32_t make_ma_oid_set(uint32_t *minor_status, gss_OID_set *ma_set,
                                int supported)
{
    gss_const_OID known_mech_attrs[] = {
        GSS_C_MA_MECH_CONCRETE,
        GSS_C_MA_MECH_PSEUDO,
        GSS_C_MA_MECH_COMPOSITE,
        GSS_C_MA_MECH_NEGO,
        GSS_C_MA_MECH_GLUE,
        GSS_C_MA_NOT_MECH,
        GSS_C_MA_DEPRECATED,
        GSS_C_MA_NOT_DFLT_MECH,
        GSS_C_MA_ITOK_FRAMED,
        GSS_C_MA_AUTH_INIT,
        GSS_C_MA_AUTH_TARG,
        GSS_C_MA_AUTH_INIT_INIT,
        GSS_C_MA_AUTH_TARG_INIT,
        GSS_C_MA_AUTH_INIT_ANON,
        GSS_C_MA_AUTH_TARG_ANON,
        GSS_C_MA_DELEG_CRED,
        GSS_C_MA_INTEG_PROT,
        GSS_C_MA_CONF_PROT,
        GSS_C_MA_MIC,
        GSS_C_MA_WRAP,
        GSS_C_MA_PROT_READY,
        GSS_C_MA_REPLAY_DET,
        GSS_C_MA_OOS_DET,
        GSS_C_MA_CBINDINGS,
        GSS_C_MA_PFS,
        GSS_C_MA_COMPRESS,
        GSS_C_MA_CTX_TRANS,
        NULL
    };
    gss_const_OID supported_mech_attrs[] = {
        GSS_C_MA_MECH_CONCRETE,
        GSS_C_MA_AUTH_INIT,
        GSS_C_MA_INTEG_PROT,
        GSS_C_MA_CONF_PROT,
        GSS_C_MA_MIC,
        GSS_C_MA_WRAP,
        GSS_C_MA_OOS_DET,
        GSS_C_MA_CBINDINGS,
        GSS_C_MA_CTX_TRANS,
        NULL
    };
    uint32_t maj = 0;
    uint32_t min = 0;
    gss_const_OID *array = known_mech_attrs;

    if (supported) {
        array = supported_mech_attrs;
    }

    maj = gss_create_empty_oid_set(&min, ma_set);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }
    for (int i = 0; array[i] != NULL; i++) {
        maj = gss_add_oid_set_member(&min, discard_const(array[i]), ma_set);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

done:
    *minor_status = min;
    return maj;
}

uint32_t gssntlm_inquire_attrs_for_mech(uint32_t *minor_status,
					gss_const_OID mech_oid,
					gss_OID_set *mech_attrs,
					gss_OID_set *known_mech_attrs)
{
    gss_OID_set s_ma = GSS_C_NULL_OID_SET;
    gss_OID_set k_ma = GSS_C_NULL_OID_SET;
    uint32_t maj = GSS_S_COMPLETE;
    uint32_t min = 0;

    if (mech_oid && !gss_oid_equal(mech_oid, &gssntlm_oid)) {
        *minor_status = ENOENT;
        return GSS_S_BAD_MECH;
    }

    if (mech_attrs != NULL) {
        maj = make_ma_oid_set(&min, &s_ma, 1);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }
    if (known_mech_attrs != NULL) {
        maj = make_ma_oid_set(&min, &k_ma, 0);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

done:
    if (maj != GSS_S_COMPLETE) {
        gss_release_oid_set(&min, &s_ma);
        gss_release_oid_set(&min, &k_ma);
    }
    if (mech_attrs != NULL) {
        *mech_attrs = s_ma;
    }
    if (known_mech_attrs != NULL) {
        *known_mech_attrs = k_ma;
    }

    *minor_status = min;
    return maj;
}
