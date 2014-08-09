/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for license */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bool gssntlm_debug_initialized = false;
bool gssntlm_debug_enabled = false;
static FILE *debug_fd = NULL;

void gssntlm_debug_init(void)
{
    char *env;

    env = secure_getenv("GSSNTLMSSP_DEBUG");
    if (env) {
        debug_fd = fopen(env, "a");
        if (debug_fd) gssntlm_debug_enabled = true;
    }
    gssntlm_debug_initialized = true;
}

void gssntlm_debug_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(debug_fd, fmt, ap);
    va_end(ap);
    fflush(debug_fd);
}
