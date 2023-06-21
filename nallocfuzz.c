#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// stacktrace
#include <execinfo.h>
#include <stdio.h>

#include<signal.h>

#include "libbacktrace/backtrace.h"

static const uint32_t fuzz_nalloc_crc32_table[] =
{
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

uint32_t fuzz_nalloc_random_state = 0;
// make sure we do not fail on init phase
uint32_t fuzz_nalloc_runs = 0;
__thread unsigned int fuzz_nalloc_running = 0;

int fuzz_nalloc_backtrace_frames = 0;
size_t fuzz_nalloc_failed_size = 0;
const char * fuzz_nalloc_failed_op = "";
#define FUZZ_NALLOC_BACKTRACE_MAXLEN 0x2000
char fuzz_nalloc_backtrace_str[FUZZ_NALLOC_BACKTRACE_MAXLEN];
size_t fuzz_nalloc_backtrace_offset = 0;
#define NALLOC_SIGNAL_MAX 32
struct sigaction fuzz_nalloc_orig_sigaction[NALLOC_SIGNAL_MAX];
void *backtrace_state;
int fuzz_nalloc_inited = 0;


// TODO have a better pseudo random function
// producing an uint32, and using provided pseudo-entropy
static inline void fuzz_nalloc_random_update(uint8_t b) {
    fuzz_nalloc_random_state = ((uint32_t)((uint32_t) fuzz_nalloc_random_state << 8)) ^ fuzz_nalloc_crc32_table[((fuzz_nalloc_random_state >> 24) ^ b) & 0xFF];
}

static void fuzz_nalloc_random_seed(const uint8_t *data, size_t size) {
    fuzz_nalloc_random_state = 0;
    fuzz_nalloc_runs++;
    for (size_t i = 0; i < size; i++) {
        fuzz_nalloc_random_update(data[i]);
    }
}

static void fuzz_nalloc_sig_handler(int signum, siginfo_t *siginfo, void *context) {
    // prints out the last faked failed allocation stack trace
    fprintf(stderr, "NULL alloc in %d run: %s(%zu) \n", fuzz_nalloc_runs, fuzz_nalloc_failed_op, fuzz_nalloc_failed_size);
    fprintf(stderr, "%s\n", fuzz_nalloc_backtrace_str);
    if (fuzz_nalloc_orig_sigaction[signum].sa_flags & SA_SIGINFO) {
        if (fuzz_nalloc_orig_sigaction[signum].sa_sigaction != NULL) {
            fuzz_nalloc_orig_sigaction[signum].sa_sigaction(signum, siginfo, context);
        }
    } else if (fuzz_nalloc_orig_sigaction[signum].sa_handler != NULL) {
        fuzz_nalloc_orig_sigaction[signum].sa_handler(signum);
    }
}

#define BACKTRACE_OK 0
#define BACKTRACE_LIMIT 1
#define BACKTRACE_EXCLUDE 2
#define BACKTRACE_OVERFLOW 3

char * fuzz_nalloc_exclude_ext = NULL;
size_t fuzz_nalloc_exclude_ext_len = 0;
uint32_t fuzz_nalloc_bitmask = 0xFF;
uint32_t fuzz_nalloc_magic = 0x294cee63;
bool fuzz_nalloc_verbose = false;

struct backtrace_data {
  size_t index;
  size_t max;
};

static void backtrace_error_donothing(void *vdata, const char *msg, int errnum) {
    // do nothing
}

static int backtrace_callback_save (void *vdata, uintptr_t pc,
          const char *filename, int lineno, const char *function) {
    struct backtrace_data *data = (struct backtrace_data *) vdata;
    if (data->index >= data->max) {
        return BACKTRACE_LIMIT;
    }
    data->index++;
    if (fuzz_nalloc_backtrace_offset < FUZZ_NALLOC_BACKTRACE_MAXLEN) {
        fuzz_nalloc_backtrace_offset += snprintf(fuzz_nalloc_backtrace_str + fuzz_nalloc_backtrace_offset, FUZZ_NALLOC_BACKTRACE_MAXLEN - fuzz_nalloc_backtrace_offset, "#%zu 0x%lx in %s %s:%d\n", data->index, pc, function, filename, lineno);
    } else {
        return BACKTRACE_OVERFLOW;
    }
    return BACKTRACE_OK;
}

static void fuzz_nalloc_save_backtrace(void) {
    struct backtrace_data data;

    data.index = 0;
    data.max = 64;
    fuzz_nalloc_backtrace_offset = 0;
    backtrace_full (backtrace_state, 0, backtrace_callback_save, backtrace_error_donothing, &data);
    if (fuzz_nalloc_verbose) {
        fprintf(stderr, "NULL alloc in %d run: %s(%zu) \n", fuzz_nalloc_runs, fuzz_nalloc_failed_op, fuzz_nalloc_failed_size);
        fprintf(stderr, "%s\n", fuzz_nalloc_backtrace_str);
    }
}

void * __interceptor_malloc(size_t);
void * __interceptor_calloc(size_t, size_t);
void * __interceptor_realloc(void*, size_t);
void * __interceptor_reallocarray(void*, size_t, size_t);

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
    if (function != NULL && strncmp(function, "__interceptor", strlen("__interceptor")) == 0) {
        return BACKTRACE_EXCLUDE;
    }
    size_t flen = strlen(filename);
    if (flen >= fuzz_nalloc_exclude_ext_len) {
        if (memcmp(filename + flen - fuzz_nalloc_exclude_ext_len, fuzz_nalloc_exclude_ext, fuzz_nalloc_exclude_ext_len) == 0) {
            return BACKTRACE_EXCLUDE;
        }
    }
    return BACKTRACE_OK;
}

static bool fuzz_nalloc_backtrace_exclude() {
    struct backtrace_data data;

    if (fuzz_nalloc_exclude_ext_len == 0) {
        return false;
    }

    data.index = 0;
    data.max = 8;
    int r = backtrace_full (backtrace_state, 0, backtrace_callback_exclude, backtrace_error_donothing, &data);
    if (r == BACKTRACE_EXCLUDE) {
        return true;
    }
    return false;
}

static bool fuzz_nalloc_fail(size_t size, const char *op) {
    if (__sync_fetch_and_add(&fuzz_nalloc_running, 1) != 1) {
        // do not fail allocations outside of fuzzer input
        // and od not fail inside of this function
        __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
        return false;
    }
    fuzz_nalloc_random_update((uint8_t) size);
    if (size >= 0x100) {
        fuzz_nalloc_random_update((uint8_t) (size >> 8));
        if (size >= 0x10000) {
            fuzz_nalloc_random_update((uint8_t) (size >> 16));
            // bigger may already fail or oom
        }
    }
    if (((fuzz_nalloc_random_state ^ fuzz_nalloc_magic) & fuzz_nalloc_bitmask) == 0 && fuzz_nalloc_runs != 1) {
        if (fuzz_nalloc_backtrace_exclude()) {
            __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
            return false;
        }
        fuzz_nalloc_failed_size = size;
        fuzz_nalloc_failed_op = op;
        fuzz_nalloc_save_backtrace();
        __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
        return true;
    }
    __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
    return false;
}


void *calloc(size_t nmemb, size_t size) {
    if (fuzz_nalloc_fail(size, "calloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __interceptor_calloc(nmemb, size);
}

void *malloc(size_t size) {
    if (fuzz_nalloc_fail(size, "malloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __interceptor_malloc(size);
}

void *realloc(void *ptr, size_t size) {
    if (fuzz_nalloc_fail(size, "realloc")) {
        errno = ENOMEM;
        return NULL;
    }
    return __interceptor_realloc(ptr, size);
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    if (fuzz_nalloc_fail(size, "reallocarray")) {
        errno = ENOMEM;
        return NULL;
    }
    return __interceptor_reallocarray(ptr, nmemb, size);
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

void fuzz_nalloc_init_post() {
    struct sigaction new_action;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_sigaction = fuzz_nalloc_sig_handler;
    new_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction (SIGSEGV, &new_action, &fuzz_nalloc_orig_sigaction[SIGSEGV]);
    sigaction (SIGABRT, &new_action, &fuzz_nalloc_orig_sigaction[SIGABRT]);
    sigaction (SIGALRM, &new_action, &fuzz_nalloc_orig_sigaction[SIGALRM]);
    sigaction (SIGINT, &new_action, &fuzz_nalloc_orig_sigaction[SIGINT]);
    sigaction (SIGTERM, &new_action, &fuzz_nalloc_orig_sigaction[SIGTERM]);
    sigaction (SIGBUS, &new_action, &fuzz_nalloc_orig_sigaction[SIGBUS]);
    sigaction (SIGFPE, &new_action, &fuzz_nalloc_orig_sigaction[SIGFPE]);
    sigaction (SIGXFSZ, &new_action, &fuzz_nalloc_orig_sigaction[SIGXFSZ]);
    sigaction (SIGUSR1, &new_action, &fuzz_nalloc_orig_sigaction[SIGUSR1]);
    sigaction (SIGUSR2, &new_action, &fuzz_nalloc_orig_sigaction[SIGUSR2]);
    fuzz_nalloc_inited = 1;
}

int NaloFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_nalloc_random_seed(data, size);
    if (__sync_fetch_and_add(&fuzz_nalloc_running, 1)) {
        __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
        return 0;
    }
    if (fuzz_nalloc_inited == 0) {
        fuzz_nalloc_init_post();
    }
    int r = LLVMFuzzerTestOneInput(data, size);
    __sync_fetch_and_sub(&fuzz_nalloc_running, 1);
    return r;
}

void error_callback_create (void *data, const char *msg, int errnum) {
    fprintf (stderr, "%s", msg);
    if (errnum > 0) {
        fprintf (stderr, ": %s", strerror (errnum));
    }
    fprintf (stderr, "\n");
}

void fuzz_nalloc_init(const char * prog) {
    fuzz_nalloc_exclude_ext = getenv("NALLOC_FUZZ_EXCLUDE_EXT");
    if (fuzz_nalloc_exclude_ext == NULL) {
        fuzz_nalloc_exclude_ext = ".rs";
    }
    fuzz_nalloc_exclude_ext_len = strlen(fuzz_nalloc_exclude_ext);

    char * bitmask = getenv("NALLOC_FUZZ_FREQ");
    if (bitmask) {
        int shift = atoi(bitmask);
        if (shift > 0 && shift < 31) {
            fuzz_nalloc_bitmask = 1 << shift;
        }
    }

    char * magic = getenv("NALLOC_FUZZ_MAGIC");
    if (magic) {
        fuzz_nalloc_magic = (uint32_t) strtol(magic, NULL, 0);
    }

    char * verbose = getenv("NALLOC_FUZZ_VERBOSE");
    if (verbose) {
        fuzz_nalloc_verbose = true;
    }

    backtrace_state = backtrace_create_state (prog, 1, error_callback_create, NULL);
}


int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const uint8_t *Data, size_t Size));

int main(int argc, char **argv) {
    fuzz_nalloc_init(argv[0]);
    return LLVMFuzzerRunDriver(&argc, &argv, NaloFuzzerTestOneInput);
}
