#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <execinfo.h>
#include <stdio.h>

#include "libbacktrace/backtrace.h"

void *backtrace_state;
size_t nalloc_exclude_size = 0;
char * nalloc_exclude_op = NULL;
char * nalloc_exclude_caller = NULL;

#define NALLOC_RUN_BACKTRACE_MAXLEN 0x2000
char nalloc_run_backtrace_str[NALLOC_RUN_BACKTRACE_MAXLEN];
size_t nalloc_run_backtrace_offset = 0;

#define BACKTRACE_OK 0
#define BACKTRACE_LIMIT 1
#define BACKTRACE_NALLOC 2

struct backtrace_data {
  size_t index;
  size_t max;
};

static void backtrace_error_donothing(void *vdata, const char *msg, int errnum) {
    // do nothing
}

void * __libc_malloc(size_t);
void * __libc_calloc(size_t, size_t);
void * __libc_realloc(void*, size_t);
void * __libc_reallocarray(void*, size_t, size_t);

static int backtrace_callback_exclude (void *vdata, uintptr_t pc,
          const char *filename, int lineno, const char *function) {
    struct backtrace_data *data = (struct backtrace_data *) vdata;
    if (data->index >= data->max) {
        return BACKTRACE_LIMIT;
    }
    data->index++;
    if (filename == NULL) {
        return BACKTRACE_OK;
    }
    if (nalloc_run_backtrace_offset < NALLOC_RUN_BACKTRACE_MAXLEN) {
        nalloc_run_backtrace_offset += snprintf(nalloc_run_backtrace_str + nalloc_run_backtrace_offset, NALLOC_RUN_BACKTRACE_MAXLEN - nalloc_run_backtrace_offset, "#%zu 0x%lx in %s %s:%d\n", data->index, pc, function, filename, lineno);
    }
    if (function != NULL && strcmp(function, nalloc_exclude_caller) == 0) {
        return BACKTRACE_NALLOC;
    }
    return BACKTRACE_OK;
}

static bool nalloc_run_fail(size_t size, const char *op) {
    bool r = false;
    if (nalloc_exclude_size > 0) {
        if (size != nalloc_exclude_size) {
            return false;
        }
        r = true;
    }
    if (nalloc_exclude_op != NULL) {
        if (strcmp(op, nalloc_exclude_op) != 0) {
            return false;
        }
        r = true;
    }
    if (nalloc_exclude_caller != NULL) {
        struct backtrace_data data;

        data.index = 0;
        data.max = 8;
        int br = backtrace_full (backtrace_state, 0, backtrace_callback_exclude, backtrace_error_donothing, &data);
        if (br == BACKTRACE_NALLOC) {
            r = true;
        } else {
            r = false;
        }
    }
    if (r) {
        fprintf(stderr, "NULL alloc for %s(%zu) :\n", op, size);
        fprintf(stderr, "%s\n", nalloc_run_backtrace_str);
    }
    return r;
}


void *calloc(size_t nmemb, size_t size) {
    if (nalloc_run_fail(size, "calloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_calloc(nmemb, size);
}

void *malloc(size_t size) {
    if (nalloc_run_fail(size, "malloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_malloc(size);
}

void *realloc(void *ptr, size_t size) {
    if (nalloc_run_fail(size, "realloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_realloc(ptr, size);
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    if (nalloc_run_fail(size, "reallocarray")) {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_reallocarray(ptr, nmemb, size);
}

void error_callback_create (void *data, const char *msg, int errnum) {
    fprintf (stderr, "%s", msg);
    if (errnum > 0) {
        fprintf (stderr, ": %s", strerror (errnum));
    }
    fprintf (stderr, "\n");
}

__attribute__((constructor))
static void nalloc_run_init(void) {
    char * size_exclude = getenv("NALLOC_RUN_SIZE");
    if (size_exclude) {
        nalloc_exclude_size = (size_t) strtol(size_exclude, NULL, 0);
    }
    nalloc_exclude_op = getenv("NALLOC_RUN_OPERATION");
    nalloc_exclude_caller = getenv("NALLOC_RUN_CALLER");

    backtrace_state = backtrace_create_state (NULL, 1, error_callback_create, NULL);
}
