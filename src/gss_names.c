/* Copyright 2013-2022 Simo Sorce <simo@samba.org>, see COPYING for license */

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

#ifndef	HOST_NAME_MAX
#include <sys/param.h>
#define	HOST_NAME_MAX	MAXHOSTNAMELEN
#endif

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

    /* left side */
    l = p - str;
    if (s1 && l != 0) {
        r1 = strndup(str, l);
        if (!r1) {
            set_GSSERR(ENOMEM);
            goto done;
        }
    }

    /* right side */
    p++;
    l = len - (p - str);
    if (s2 && l != 0) {
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

/* Form of names allowed in GSSNTLMSSP now:
 *
 * Standard Forms:
 *  foo
 *      USERNAME: foo
 *      DOMAIN: <null>
 *
 *  BAR\foo
 *      USERNAME: foo
 *      DOMAIN: BAR
 *
 *  foo@BAR
 *      USERNAME: foo
 *      DOMAIN: BAR
 *
 * Enterprise name forms:
 *  foo\@bar.example.com
 *      USERNAME: foo@bar.example.com
 *      DOMAIN: <null>
 *
 *  foo\@bar.example.com@BAR
 *      USERNAME: foo@bar.example.com
 *      DOMAIN: BAR
 *
 *  \foo@bar.example.com
 *      USERNAME: foo@bar.example.com
 *      DOMAIN: <null>
 *
 *  BAR\foo@bar.example.com
 *      USERNAME: foo@bar.example.com
 *      DOMAIN: BAR
 *
 *  BAR@dom\foo@bar.example.com
 *      USERNAME: foo@bar.example.com
 *      DOMAIN: BAR@dom
 *
 * Invalid forms:
 *  BAR@dom\@foo..
 *  DOM\foo\@bar
 *  foo@bar\@baz
 */
#define MAX_NAME_LEN 1024
static uint32_t parse_user_name(uint32_t *minor_status,
                                const char *str, size_t len,
                                char **domain, char **username)
{
    uint32_t retmaj;
    uint32_t retmin;
    char *at, *sep;

    if (len > MAX_NAME_LEN) {
        return GSSERRS(ERR_NAMETOOLONG, GSS_S_BAD_NAME);
    }

    *username = NULL;
    *domain = NULL;

    /* let's check if there are '@' or '\' signs */
    at = memchr(str, '@', len);
    sep = memchr(str, '\\', len);

    /* Check if enterprise name first */
    if (at && sep) {
        /* we may have an enterprise name here */
        char strbuf[len + 1];
        char *buf = strbuf;
        bool domain_handled = false;

        /* copy buf to manipulate it */
        memcpy(buf, str, len);
        buf[len] = '\0';

        /* adjust pointers relative to new buffer */
        sep = buf + (sep - str);
        at = buf + (at - str);

        if (sep > at) {
            /* domain name contains an '@' sign ... */
            if (*(sep + 1) == '@') {
                /* invalid case of XXX@YYY\@ZZZ*/
                set_GSSERR(EINVAL);
                goto done;
            }
        } else if (at - sep == 1) {
            /* it's just a '\@' escape */
            /* no leading domain */
            sep = NULL;
        }

        if (sep) {
            /* leading domain, copy if domain name is not empty */
            domain_handled = true;

            /* terminate and copy domain, even if empty */
            /* NOTE: this is important for the Windbind integration case
             * where we need to tell the machinery to *not* add the default
             * domain name, it happens when the domain is NULL. */
            *sep = '\0';
            *domain = strdup(buf);
            if (NULL == *domain) {
                set_GSSERR(ENOMEM);
                goto done;
            }
            /* point buf at username part */
            len = len - (sep - buf) - 1;
            buf = sep + 1;
        }

        for (at = strchr(buf, '@'); at != NULL; at = strchr(at, '@')) {
            if (*(at - 1) == '\\') {
                if (domain_handled) {
                    /* Invalid forms like DOM\foo\@bar or foo@bar\@baz */
                    free(*domain);
                    *domain = NULL;
                    set_GSSERR(EINVAL);
                    goto done;
                }
                /* remove escape, moving all including terminating '\0' */
                memmove(at - 1, at, len - (at - buf) + 1);
            } else if (!domain_handled) {
                /* an '@' without escape and no previous
                 * domain was split out.
                 * the rest of the string is the domain */
                *at = '\0';
                *domain = strdup(at + 1);
                if (NULL == *domain) {
                    set_GSSERR(ENOMEM);
                    goto done;
                }
                /* note we continue the loop to check if any invalid
                 * \@ escapes is found in the domain part */
            }
            at += 1;
        }

        *username = strdup(buf);
        if (NULL == *username) {
            set_GSSERR(ENOMEM);
            goto done;
        }

        /* we got an enterprise name, return */
        set_GSSERRS(0, GSS_S_COMPLETE);
        goto done;
    }

    /* Check if in classic DOMAIN\User windows format */
    if (sep) {
        retmaj = string_split(&retmin, '\\', str, len, domain, username);
        goto done;
    }

    /* else accept a user@domain format too */
    if (at) {
        retmaj = string_split(&retmin, '@', str, len, username, domain);
        goto done;
    }

    /* finally, take string as simple user name */
    *username = strndup(str, len);
    if (NULL == *username) {
        set_GSSERR(ENOMEM);
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
    struct gssntlm_name *name = NULL;
    uint32_t retmaj;
    uint32_t retmin;

    /* TODO: check mech_type == gssntlm_oid */
    if (mech_type == GSS_C_NO_OID) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
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
        char *spn = NULL;
        char *p = NULL;

        name->type = GSSNTLM_NAME_SERVER;

        if (input_name_buffer->length > 0) {
            spn = strndup(input_name_buffer->value, input_name_buffer->length);
            if (!spn) {
                set_GSSERR(ENOMEM);
                goto done;
            }
            p = strchr(spn, '@');
            if (p && input_name_buffer->length == 1) {
                free(spn);
                spn = p = NULL;
            }
        }

        if (p) {
            /* Windows expects a SPN not a GSS Name */
            if (p != spn) {
                *p = '/';
                name->data.server.spn = spn;
                spn = NULL;
            }
            p += 1;
            name->data.server.name = strdup(p);
            if (!name->data.server.name) {
                free(spn);
                set_GSSERR(ENOMEM);
                goto done;
            }
        } else {
            char hostname[HOST_NAME_MAX + 1] = { 0 };
            size_t l, r;
            /* no seprator, assume only service is provided and try to
             * source the local host name */
            retmin = gethostname(hostname, HOST_NAME_MAX);
            if (retmin) {
                free(spn);
                set_GSSERR(retmin);
                goto done;
            }
            hostname[HOST_NAME_MAX] = '\0';
            if (spn != NULL) {
                /* spn = <service> + </> + <hostname> + <\0> */
                l = strlen(spn) + 1 + strlen(hostname) + 1;
                name->data.server.spn = malloc(l);
                if (!name->data.server.spn) {
                    free(spn);
                    set_GSSERR(ENOMEM);
                    goto done;
                }
                r = snprintf(name->data.server.spn, l, "%s/%s", spn, hostname);
                if (r != l - 1) {
                    free(spn);
                    set_GSSERR(ENOMEM);
                    goto done;
                }
            }
            name->data.server.name = strdup(hostname);
            if (!name->data.server.name) {
                free(spn);
                set_GSSERR(ENOMEM);
                goto done;
            }
        }
        free(spn);
        set_GSSERRS(0, GSS_S_COMPLETE);

    } else if (gss_oid_equal(input_name_type, GSS_C_NT_USER_NAME)) {

        name->type = GSSNTLM_NAME_USER;
        retmaj = parse_user_name(&retmin,
                                 input_name_buffer->value,
                                 input_name_buffer->length,
                                 &name->data.user.domain,
                                 &name->data.user.name);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_MACHINE_UID_NAME)) {
        uid_t uid;

        name->type = GSSNTLM_NAME_USER;
        name->data.user.domain = NULL;

        uid = *(uid_t *)input_name_buffer->value;
        retmaj = uid_to_name(&retmin, uid, &name->data.user.name);
    } else if (gss_oid_equal(input_name_type, GSS_C_NT_STRING_UID_NAME)) {
        char struid[12] = { 0 };
        uid_t uid;

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

size_t gssntlm_get_attrs_count(const struct gssntlm_name_attribute *attrs)
{
    size_t c;
    for (c = 0; attrs && attrs[c].attr_name != NULL; c++) ;
    return c;
}

int gssntlm_copy_attrs(const struct gssntlm_name_attribute *src,
                       struct gssntlm_name_attribute **dst)
{
    struct gssntlm_name_attribute *copied_attrs;
    size_t attrs_count = gssntlm_get_attrs_count(src);

    *dst = NULL;
    if (attrs_count == 0) {
        return 0;
    }

    copied_attrs = calloc(attrs_count + 1, /* +1 for terminator entry */
                          sizeof(struct gssntlm_name_attribute));
    if (copied_attrs == NULL) {
        return ENOMEM;
    }

    for (size_t i = 0; i < attrs_count; i++) {
        copied_attrs[i].attr_name = strdup(src[i].attr_name);
        if (copied_attrs[i].attr_name == NULL) {
            gssntlm_release_attrs(&copied_attrs);
            return ENOMEM;
        }
        copied_attrs[i].attr_value.length = src[i].attr_value.length;
        copied_attrs[i].attr_value.value = malloc(src[i].attr_value.length);
        if (copied_attrs[i].attr_value.value == NULL) {
            gssntlm_release_attrs(&copied_attrs);
            return ENOMEM;
        }
        memcpy(copied_attrs[i].attr_value.value, src[i].attr_value.value,
               src[i].attr_value.length);
    }
    /* terminator entry is filled with zeroes by calloc */

    *dst = copied_attrs;
    return 0;
}

struct gssntlm_name_attribute *gssntlm_find_attr(
                                        struct gssntlm_name_attribute *attrs,
                                        const char *attr_name,
                                        size_t attr_name_len)
{
    for (size_t i = 0; attrs && (attrs[i].attr_name != NULL); i++) {
        /* We store attr_name as a zero-terminated string, so
         * it is always zero-terminated */
        if (attr_name_len == strlen(attrs[i].attr_name) &&
            strncasecmp(attrs[i].attr_name, attr_name, attr_name_len) == 0) {
            return &attrs[i];
        }
    }
    return NULL;
}

void gssntlm_release_attrs(struct gssntlm_name_attribute **attrs)
{
    for (size_t i = 0; *attrs && (*attrs)[i].attr_name != NULL; i++) {
        free((*attrs)[i].attr_name);
        free((*attrs)[i].attr_value.value);
    }
    safefree(*attrs);
}

int gssntlm_copy_name(struct gssntlm_name *src, struct gssntlm_name *dst)
{
    char *dom = NULL, *usr = NULL, *spn = NULL, *srv = NULL;
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
        if (src->data.server.spn) {
            spn = strdup(src->data.server.spn);
            if (!spn) {
                ret = ENOMEM;
                goto done;
            }
        }
        dst->data.server.spn = spn;
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

    ret = gssntlm_copy_attrs(src->attrs, &dst->attrs);
    if (ret) goto done;

    ret = 0;
done:
    if (ret) {
        safefree(dom);
        safefree(usr);
        safefree(spn);
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
        safefree(name->data.server.spn);
        safefree(name->data.server.name);
        break;
    }
    gssntlm_release_attrs(&name->attrs);
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
        out->value = strdup(in->data.server.spn);
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

uint32_t netbios_get_names(void *ctx, char *computer_name,
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
        ret = external_netbios_get_names(ctx,
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
    uint32_t retmin = 0;
    uint32_t retmaj = 0;
    uint32_t tmpmin;
    const struct gssntlm_name *in = (const struct gssntlm_name *)name;

    if (!attrs) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    *attrs = GSS_C_NO_BUFFER_SET;

    if (name == GSS_C_NO_NAME) {
        return GSSERRS(GSS_S_BAD_NAME, GSS_S_CALL_INACCESSIBLE_READ);
    }

    for (size_t i = 0; in->attrs && in->attrs[i].attr_name != NULL; i++) {
        struct gssntlm_name_attribute *attr = &in->attrs[i];
        size_t attr_name_len = strlen(attr->attr_name);
        gss_buffer_desc buf;
        gss_buffer_t attr_value = &attr->attr_value;
        /* +1 for '=' separator and +1 for EOL */
        size_t full_string_len = attr_value->length + attr_name_len + 2;
        size_t offset = 0;
        char *attr_string = malloc(full_string_len);
        if (attr_string == NULL) {
            set_GSSERR(ENOMEM);
            goto done;
        }

        /* Construct 'attr_name=<attr_value>\0' string */
        memcpy(attr_string, attr->attr_name, attr_name_len);
        offset += attr_name_len;

        attr_string[offset++] = '=';

        memcpy(attr_string + offset, attr_value->value, attr_value->length);
        offset += attr_value->length;

        attr_string[offset] = 0;

        /* now add a buffer to output set */
        buf.length = full_string_len;
        buf.value = attr_string;
        retmaj = gss_add_buffer_set_member(&retmin, &buf, attrs);
        free(attr_string);
        if (retmaj != GSS_S_COMPLETE) goto done;
    }

done:
    if (retmaj) {
        (void)gss_release_buffer_set(&tmpmin, attrs);
    }
    return GSSERRS(retmin, retmaj);
}

/* RFC6680 - GSSAPI Naming Extensions */
uint32_t gssntlm_get_name_attribute(uint32_t *minor_status,
                                    gss_name_t name,
                                    gss_buffer_t attr,
                                    int *authenticated,
                                    int *complete,
                                    gss_buffer_t value,
                                    gss_buffer_t display_value,
                                    int *more)
{
    uint32_t retmin;
    uint32_t retmaj;
    const struct gssntlm_name *in = (const struct gssntlm_name *)name;
    struct gssntlm_name_attribute *found_attr;

    if (name == GSS_C_NO_NAME) {
        return GSSERRS(GSS_S_BAD_NAME, GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (attr == NULL) {
        return GSSERRS(ERR_NOARG, GSS_S_CALL_INACCESSIBLE_READ);
    }

    if (display_value) {
        display_value->value = NULL;
        display_value->length = 0;
    }
    if (more) { *more = 0; }
    if (authenticated) { *authenticated = 0; }
    if (complete) { *complete = 0; }

    found_attr = gssntlm_find_attr(in->attrs, attr->value, attr->length);
    if (!found_attr) {
        return GSSERRS(ENOENT, GSS_S_UNAVAILABLE);
    }

    if (authenticated) { *authenticated = 1; }
    if (complete) { *complete = 1; }
    if (value) {
        gss_buffer_t attr_value = &found_attr->attr_value;
        value->value = malloc(attr_value->length);
        if (!value->value) {
            return GSSERRS(ENOMEM, GSS_S_FAILURE);
        }
        memcpy(value->value, attr_value->value, attr_value->length);
        value->length = attr_value->length;
    }
    return GSSERRS(0, GSS_S_COMPLETE);
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
