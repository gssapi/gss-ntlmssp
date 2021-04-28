/* Copyright (C) 2014 GSS-NTLMSSP contributors, see COPYING for license */

#ifndef _GSSNTLMSSP_DEBUG_H_
#define _GSSNTLMSSP_DEBUG_H_

#include <stdbool.h>
#include <time.h>

extern gss_OID_desc gssntlm_debug_oid;
extern bool gssntlm_debug_initialized;
extern int gssntlm_debug_fd;

void gssntlm_debug_init(void);
void gssntlm_debug_printf(const char *fmt, ...);

#define unlikely(x) __builtin_expect(!!(x), 0)

static inline int debug_gss_errors(const char *function,
                                   const char *file,
                                   unsigned int line,
                                   unsigned int maj,
                                   unsigned int min)
{
    if (unlikely(gssntlm_debug_initialized == false)) {
        gssntlm_debug_init();
    }
    if (unlikely(gssntlm_debug_fd != -1)) {
        gssntlm_debug_printf("[%ld] %s: %s() @ %s:%u [%u:%u]\n",
                             (long)time(NULL),
                             GSS_ERROR(maj) ? "ERROR" : "ALLOK",
                             function, file, line, maj, min);
    }
    return 0;
}
#define DEBUG_GSS_ERRORS(maj, min) \
    debug_gss_errors(__FUNCTION__, __FILE__, __LINE__, maj, min)

int gssntlm_debug_invoke(gss_buffer_t value);

#endif /* _GSSNTLMSSP_DEBUG_H_ */
