/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for license */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gssapi_ntlmssp.h"

#define OPEN_FLAGS O_WRONLY | O_CREAT | O_APPEND| O_CLOEXEC
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;
bool gssntlm_debug_initialized = false;
int gssntlm_debug_fd = -1;

void gssntlm_debug_init(void)
{
    char *env;

    if (gssntlm_debug_initialized) return;

    pthread_mutex_lock(&debug_mutex);

    env = secure_getenv("GSSNTLMSSP_DEBUG");
    if (env) {
        gssntlm_debug_fd = open(env, OPEN_FLAGS, 0660);
    }
    gssntlm_debug_initialized = true;

    pthread_mutex_unlock(&debug_mutex);
}

void gssntlm_debug_printf(const char *fmt, ...)
{
    va_list ap;

    if (gssntlm_debug_fd == -1) return;

    va_start(ap, fmt);
    vdprintf(gssntlm_debug_fd, fmt, ap);
    va_end(ap);
    fdatasync(gssntlm_debug_fd);
}

static int gssntlm_debug_enable(const char *filename)
{
    int old_debug_fd = gssntlm_debug_fd;
    int new_debug_fd = -1;
    int ret = 0;

    pthread_mutex_lock(&debug_mutex);

    gssntlm_debug_initialized = true;

    new_debug_fd = open(filename, OPEN_FLAGS, 0660);
    if (new_debug_fd == -1) {
        ret = errno;
    }

    gssntlm_debug_fd = new_debug_fd;

    if (old_debug_fd != -1) {
        close(old_debug_fd);
    }

    pthread_mutex_unlock(&debug_mutex);

    return ret;
}

static int gssntlm_debug_disable(void)
{
    int old_debug_fd = gssntlm_debug_fd;
    int ret = 0;

    pthread_mutex_lock(&debug_mutex);

    gssntlm_debug_fd = -1;

    if (old_debug_fd != -1) {
        ret = close(old_debug_fd);
    }

    pthread_mutex_unlock(&debug_mutex);

    return ret;
}

gss_OID_desc gssntlm_debug_oid = {
    GSS_NTLMSSP_DEBUG_OID_LENGTH,
    discard_const(GSS_NTLMSSP_DEBUG_OID_STRING)
};

int gssntlm_debug_invoke(gss_buffer_t value)
{
    char filename[PATH_MAX] = { 0 };

    if (value->length > PATH_MAX - 1) {
        return EINVAL;
    }

    if ((value->length != 0) &&
        (((char *)value->value)[0] != '\0')) {
        memcpy(filename, value->value, value->length);
        filename[value->length] = '\0';
    }

    if (filename[0] == '\0') {
        return gssntlm_debug_disable();
    }

    return gssntlm_debug_enable(filename);
}
