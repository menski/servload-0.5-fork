/* $Id: servload.c 1971 2012-01-10 14:37:52Z umaxx $ */

/*
 * Copyright (c) 2011 Jörg Zinke <info@salbnet.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <getopt.h>
#include <math.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ((size_t)-1)
#endif

#ifndef SIGINFO
#define SIGINFO SIGUSR1
#endif

#define SVL_EXPAND(token) #token
#define SVL_QUOTE(token) SVL_EXPAND(token)

#define SVL_VERSION "0.5"
#define SVL_YEAR "2011"

#define SVL_INT_BITS (sizeof(int) * CHAR_BIT)

#define SVL_PREFIX_NANO (1e-9)
#define SVL_PREFIX_MICRO (1e-6)
#define SVL_PREFIX_MILLI (1e-3)

#define SVL_PREFIX_KILO (1024)
#define SVL_PREFIX_MEGA (1024 * 1024)
#define SVL_PREFIX_GIGA (1024 * 1024 * 1024)

#define SVL_ANSI_SC "\x1b[s" /* store cursor */
#define SVL_ANSI_RC "\x1b[u" /* restore cursor */
#define SVL_ANSI_CE "\x1b[K" /* clear eol */
#define SVL_ANSI_SF "\x1b[%luS" /* scroll forward */
#define SVL_ANSI_CM "\x1b[%lu;%luH" /* cursor move */

#define SVL_REQUEST_SLA 5
#define SVL_REQUEST_TIMEOUT 300

enum { SVL_ERROR = -1, SVL_SUCCESS };
enum { SVL_UNDEFINED = -1, SVL_FALSE, SVL_TRUE };

enum { SVL_SCORE = 50 }; /* score threshold */
enum { SVL_TIC = 4, SVL_MARGIN = 6, SVL_HASH = 33, SVL_STATUS = 10000 };

enum { SVL_POOL_RESERVED = 3, SVL_POLL_TIMEOUT = 10 };

enum { SVL_FLAG_PIPELINE = 1, SVL_FLAG_CLONE = 2, SVL_FLAG_TIMER = 4,
       SVL_FLAG_CLOSE = 8, SVL_FLAG_EOF = 16, SVL_FLAG_DONE = 32 };

enum { SVL_HTTP_STATUS, SVL_HTTP_CONTINUE, SVL_HTTP_HEADER, SVL_HTTP_BODY };
enum { SVL_HTTP_BODY_EOF, SVL_HTTP_BODY_EMPTY, SVL_HTTP_BODY_CHUNK,
       SVL_HTTP_BODY_CONTENT, SVL_HTTP_BODY_MULTIPART };

typedef double  svl_timestamp_t;

typedef struct svl_buffer {
    void *pointer;
    size_t offset, length, size;
} svl_buffer_t;

typedef struct svl_url {
    char scheme[NI_MAXSERV + 1], host[NI_MAXHOST + 1], port[NI_MAXSERV + 1];
} svl_url_t;

typedef struct svl_address {
    int family, type, protocol;
    struct sockaddr_storage storage;
    socklen_t size;
} svl_address_t;

typedef struct svl_file {
    const char *path;
    int descriptor;
    svl_buffer_t *buffer;
} svl_file_t;

typedef struct svl_method {
    const char *name;
    unsigned short factor;
} svl_method_t;

typedef struct svl_request {
    svl_buffer_t *buffer;
    svl_timestamp_t timestamp, wait;
    unsigned int flags;
    char *key;
    svl_timestamp_t start, response;
    struct svl_request *previous, *next;
} svl_request_t;

typedef struct svl_request_dns {
    svl_request_t request;
    /* todo */
} svl_request_dns_t;

typedef struct svl_request_http {
    svl_request_t request;
    unsigned int status, state, body;
    size_t bytes;
    size_t response;
} svl_request_http_t;

typedef struct svl_session {
    const char *key;
    size_t id, length;
    svl_timestamp_t duration;
    double thinktime, bytes;
    unsigned short score;
    int last;
    struct svl_session *next;
} svl_session_t;

typedef struct svl_hash {
    svl_session_t **sessions;
    size_t buckets, length;
} svl_hash_t;

typedef struct svl_histogram {
    unsigned long *frequency, *clones, maximum;
    size_t length;
} svl_histogram_t;

typedef struct svl_sequence {
    svl_request_t **requests;
    svl_hash_t *sessions;
    size_t length;
    svl_timestamp_t duration;
    svl_histogram_t *histogram;
} svl_sequence_t;

typedef struct svl_queue {
    svl_request_t *head, *tail;
} svl_queue_t;

typedef struct svl_connection {
    struct pollfd *descriptor;
    SSL *ssl;
    svl_queue_t *write, *read;
    svl_buffer_t *buffer;
    svl_timestamp_t open;
    struct svl_connection *previous, *next;
} svl_connection_t;

typedef struct svl_list {
    svl_connection_t *head, *tail, *next;
    size_t length;
} svl_list_t;

typedef struct svl_pool {
    svl_connection_t *connections;
    struct pollfd *descriptors;
    int events;
    size_t length;
    svl_list_t *busy, *free;
} svl_pool_t;

typedef struct svl_statistic {
    svl_timestamp_t duration, *connects, *responses;
    size_t connections, requests, bytes, error, done;
    unsigned long econnreset, etimedout, econnrefused, sla, timeout, pipeline;
} svl_statistic_t;

typedef struct svl_statistic_dns {
    svl_statistic_t statistic;
    /* todo */
} svl_statistic_dns_t;

typedef struct svl_statistic_http {
    svl_statistic_t statistic;
    unsigned long mismatch, not_found, server_error;
} svl_statistic_http_t;

typedef struct svl_context {
    svl_url_t *url;
    svl_address_t *address;
    SSL_CTX *ssl_context;
    svl_file_t *file;
    svl_method_t *method;
    svl_sequence_t *sequence;
    svl_pool_t *pool;
    size_t queue;
    size_t timer;
    svl_statistic_t *statistic;
} svl_context_t;

static unsigned long svl_round(double);
static void *svl_calloc(size_t, size_t);
static void *svl_crealloc(void *, size_t, size_t, size_t);
static size_t svl_asprintf(char **, const char *, ...);
static char *svl_strtrim(char *);
static void svl_continue(void);
static int svl_ulong_compare(const void *, const void *);
static double svl_ulong_median(unsigned long *, size_t);
static svl_timestamp_t svl_timestamp_now(void);
static svl_timestamp_t svl_timestamp_dns(const char *);
static svl_timestamp_t svl_timestamp_http(const char *);
static int svl_timestamp_compare(const void *, const void *);
static double svl_timestamp_median(svl_timestamp_t *, size_t);
static void svl_buffer_append(svl_buffer_t *, const void *, size_t);
static void svl_buffer_expand(svl_buffer_t *, size_t);
static char *svl_buffer_line(svl_buffer_t *);
static void svl_buffer_compact(svl_buffer_t *);
static void svl_buffer_free(svl_buffer_t *);
static void svl_url_parse(svl_url_t *, const char *);
static void svl_address_resolve(svl_address_t *, svl_url_t *);
static void svl_file_setup(svl_file_t *, const char *);
static void svl_file_open(svl_file_t *);
static ssize_t svl_file_read(svl_file_t *);
static void svl_file_close(svl_file_t *);
static void svl_file_free(svl_file_t *);
static void svl_method_parse(svl_method_t *, const char *, const char *);
static void svl_request_setup(svl_request_t *);
static int svl_request_timeout(svl_request_t *);
static void svl_request_link(svl_request_t *, svl_request_t *);
static void svl_request_unlink(svl_request_t *);
static int svl_request_compare_timestamp(const void *, const void *);
static int svl_request_compare_wait(const void *, const void *);
static double svl_request_median_wait(svl_request_t **, size_t);
static void svl_request_free(svl_request_t *);
static void svl_request_dns_parse(svl_request_dns_t *, svl_url_t *, char *);
static void svl_request_dns_response(svl_request_dns_t *request, svl_statistic_dns_t *, svl_buffer_t *);
static void svl_request_http_parse(svl_request_http_t *, svl_url_t *, char *);
static void svl_request_http_response(svl_request_http_t *, svl_statistic_http_t *, svl_buffer_t *);
static void svl_request_http_status(svl_request_http_t *, svl_statistic_http_t *, svl_buffer_t *);
static void svl_request_http_header(svl_request_http_t *, svl_buffer_t *);
static void svl_request_http_body(svl_request_http_t *, svl_buffer_t *);
static int svl_request_http_compare_bytes(const void *, const void *);
static double svl_request_http_median_bytes(svl_request_http_t **, size_t);
static int svl_session_compare_length(const void *, const void *);
static int svl_session_compare_duration(const void *, const void *);
static int svl_session_compare_thinktime(const void *, const void *);
static int svl_session_compare_bytes(const void *, const void *);
static double svl_session_median_length(svl_session_t **, size_t);
static double svl_session_median_duration(svl_session_t **, size_t);
static double svl_session_median_thinktime(svl_session_t **, size_t);
static double svl_session_median_bytes(svl_session_t **, size_t);
static size_t svl_hash(const char *);
static void svl_hash_setup(svl_hash_t *, size_t);
static svl_session_t *svl_hash_lookup(svl_hash_t *, const char *);
static svl_session_t *svl_hash_insert(svl_hash_t *, const char *);
static void svl_hash_free(svl_hash_t *);
static void svl_histogram_setup(svl_histogram_t *, size_t);
static void svl_histogram_frequency(svl_histogram_t *, svl_request_t **, size_t);
static void svl_histogram_plot(svl_histogram_t *);
static void svl_histogram_free(svl_histogram_t *);
static void svl_sequence_setup(svl_sequence_t *);
static void svl_sequence_load(svl_sequence_t *, svl_url_t *, svl_file_t *);
static svl_request_t * svl_sequence_append(svl_sequence_t *, svl_url_t *);
static void svl_sequence_analyse(svl_sequence_t *);
static void svl_sequence_modify(svl_sequence_t *, svl_url_t *, svl_method_t *);
static void svl_sequence_multiply(svl_sequence_t *, svl_url_t *, unsigned int);
static void svl_sequence_peak(svl_sequence_t *, svl_url_t *, unsigned int);
static void svl_sequence_score(svl_sequence_t *, svl_url_t *, unsigned int);
static void svl_sequence_metric(svl_sequence_t *, svl_url_t *);
static unsigned short svl_sequence_normalize(svl_url_t *, double, double);
static void svl_sequence_clone(svl_sequence_t *, svl_url_t *, size_t, unsigned int);
static void svl_sequence_prepare(svl_sequence_t *, svl_url_t *, svl_method_t *);
static void svl_sequence_plot(svl_sequence_t *);
static void svl_sequence_status(svl_sequence_t *, const char *, ...);
static void svl_sequence_free(svl_sequence_t *);
static void svl_queue_push(svl_queue_t *, svl_request_t *);
static svl_request_t *svl_queue_peek(svl_queue_t *);
static svl_request_t *svl_queue_pop(svl_queue_t *);
static void svl_connection_setup(svl_connection_t *, struct pollfd *);
static void svl_connection_open(svl_connection_t *, svl_address_t *, SSL_CTX *);
static void svl_connection_write(svl_connection_t *, svl_statistic_t *);
static void svl_connection_read(svl_connection_t *, svl_statistic_t *, svl_url_t *);
static void svl_connection_close(svl_connection_t *);
static void svl_connection_error(svl_connection_t *, svl_statistic_t *, int);
static void svl_connection_process(svl_connection_t *, svl_statistic_t *, svl_url_t *);
static void svl_connection_timeout(svl_connection_t *, svl_statistic_t *);
static int svl_connection_busy(svl_connection_t *);
static int svl_connection_event(svl_connection_t *);
static void svl_connection_link(svl_connection_t *, svl_connection_t *);
static void svl_connection_unlink(svl_connection_t *);
static void svl_connection_free(svl_connection_t *);
static void svl_list_append(svl_list_t *, svl_connection_t *);
static svl_connection_t * svl_list_head(svl_list_t *);
static svl_connection_t * svl_list_next(svl_list_t *);
static void svl_list_remove(svl_list_t *, svl_connection_t *);
static void svl_pool_setup(svl_pool_t *, size_t);
static void svl_pool_open(svl_pool_t *, svl_address_t *, SSL_CTX *);
static void svl_pool_poll(svl_pool_t *);
static void svl_pool_process(svl_pool_t *, svl_statistic_t *, svl_url_t *);
static void svl_pool_status(svl_pool_t *);
static void svl_pool_free(svl_pool_t *);
static void svl_statistic_connect(svl_statistic_t *, svl_timestamp_t);
static void svl_statistic_response(svl_statistic_t *, svl_timestamp_t);
static void svl_statistic_status(svl_statistic_t *);
static void svl_statistic_print(svl_statistic_t *);
static void svl_statistic_bytes(double);
static void svl_statistic_free(svl_statistic_t *);
static void svl_statistic_dns_print(svl_statistic_dns_t *);
static void svl_statistic_http_print(svl_statistic_http_t *);
static void svl_context_setup(svl_context_t *, const char *, const char *, const char *, const char *);
static void svl_context_setting(svl_context_t *);
static void svl_context_timer(svl_context_t *);
static void svl_context_status(svl_context_t *);
static void svl_context_process(svl_context_t *);
static void svl_context_statistic(svl_context_t *);
static void svl_context_free(svl_context_t *);
static void svl_exit(void);
static void svl_signal(int);

static volatile sig_atomic_t svl_alarm = SVL_TRUE;
static volatile sig_atomic_t svl_terminate = SVL_FALSE;
static volatile sig_atomic_t svl_info = SVL_FALSE;

static svl_context_t *svl_context = NULL;

static unsigned long 
svl_round(double value) {
    if (value < 0 || value > ULONG_MAX - 0.5)
        errx(EX_SOFTWARE, "unsigned long overflow");
    return (unsigned long)(value + 0.5);
}

static void *
svl_calloc(size_t count, size_t size) {
    void *pointer;

    if ((pointer = calloc(count, size)) == NULL)
        err(EX_OSERR, "calloc failed");
    return pointer;
}

static void *
svl_crealloc(void *pointer, size_t old_count, size_t new_count, size_t size) {
    size_t old_size = old_count * size;
    size_t new_size = new_count * size;
    void *new_pointer;

    if (SIZE_T_MAX / new_count < size)
        errx(EX_SOFTWARE, "realloc overflow");
    if ((new_pointer = realloc(pointer, new_size)) == NULL)
        err(EX_OSERR, "realloc failed");
    if (new_size > old_size)
        memset((char *)new_pointer + old_size, 0, new_size - old_size);
    return new_pointer;
}

static size_t
svl_asprintf(char **string, const char *format, ...) {
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vasprintf(string, format, arguments);
    va_end(arguments);
    if (result == SVL_ERROR) {
        *string = NULL;
        err(EX_OSERR, "vasprintf failed");
    }
    return (size_t)result;
}

static char *
svl_strtrim(char *string) {
    char *end = string + strlen(string) - 1;

    while(isspace(*string))
        string++;
    while(end > string && isspace(*end))
        *end-- = '\0';
    return string;
}

static void
svl_continue(void) {
    char character;

    printf("Continue [Y/n]: ");
    fflush(stdout);
    if ((character = tolower(getchar())) == EOF && ferror(stdin)) /* todo: stdin EOF? -> || ferror(stdin) */
        err(EX_OSERR, "getchar failed");
    if (character == 'n')
        svl_terminate = SVL_TRUE; /* todo: empty stdin until \n? */
    fflush(stdout);
}

static int
svl_ulong_compare(const void *pointer_a, const void *pointer_b) {
    const unsigned long *value_a = (const unsigned long *) pointer_a;
    const unsigned long *value_b = (const unsigned long *) pointer_b;

    return (*value_a > *value_b) - (*value_a < *value_b);
}

static double
svl_ulong_median(unsigned long *array, size_t length) {
    qsort(array, length, sizeof(unsigned long), svl_ulong_compare);
    if (length % 2 != 0)
        return array[length / 2];
    else
        return (array[length / 2 - 1] + array[length / 2]) / 2.0;
}

static svl_timestamp_t
svl_timestamp_now(void) {
    svl_timestamp_t timestamp;
    struct timespec monotonic;

    memset(&monotonic, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic) == SVL_ERROR)
        err(EX_OSERR, "clock_gettime failed");
    /* todo: check for overflow */
    timestamp = monotonic.tv_sec + monotonic.tv_nsec * SVL_PREFIX_NANO;
    return timestamp;
}

static svl_timestamp_t
svl_timestamp_dns(const char *string) {
    /* todo */
    (void)string; /* silence compiler warning until implemented */
    return 0;
}

static svl_timestamp_t
svl_timestamp_http(const char *string) {
    const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", 
                             "Aug", "Sep", "Oct", "Nov", "Dec", NULL };
    char month[4] = { 0 };
    double seconds, fractional, integral;
    struct tm date;
    time_t calendar;
    unsigned int i;

    memset(&date, 0, sizeof(struct tm));
    if (sscanf(string, "%02d/%03[a-zA-Z]/%04d:%02d:%02d:%lf", &date.tm_mday, month, &date.tm_year, &date.tm_hour, &date.tm_min, &seconds) != 6)
        err(EX_DATAERR, "time failed");
    fractional = modf(seconds, &integral);
    date.tm_sec = (int)integral;
    for (i = 0, date.tm_mon = SVL_UNDEFINED; months[i] != NULL; i++)
        if (strncasecmp(month, months[i], 3) == 0)
            date.tm_mon = i;
    if (date.tm_mon == SVL_UNDEFINED)
        errx(EX_DATAERR, "month failed");
    date.tm_year -= 1900;
    date.tm_isdst = SVL_UNDEFINED;
    if ((calendar = mktime(&date)) == SVL_ERROR)
        errx(EX_DATAERR, "mktime failed");
    return calendar + fractional;
}

static int
svl_timestamp_compare(const void *pointer_a, const void *pointer_b) {
    const svl_timestamp_t *timestamp_a = (const svl_timestamp_t *) pointer_a;
    const svl_timestamp_t *timestamp_b = (const svl_timestamp_t *) pointer_b;

    return (*timestamp_a > *timestamp_b) - (*timestamp_a < *timestamp_b);
}

static double
svl_timestamp_median(svl_timestamp_t *timestamps, size_t length) {
    qsort(timestamps, length, sizeof(svl_timestamp_t), svl_timestamp_compare);
    if (length % 2 != 0)
        return timestamps[length / 2];
    else
        return (timestamps[length / 2 - 1] + timestamps[length / 2]) / 2.0;
}

static void
svl_buffer_append(svl_buffer_t *buffer, const void *data, size_t length) {
    svl_buffer_expand(buffer, length);
    memmove((char *)buffer->pointer + buffer->length, data, length);
    buffer->length += length;
}

static void
svl_buffer_expand(svl_buffer_t *buffer, size_t size) {
    if (SIZE_T_MAX - size <= buffer->size)
        errx(EX_SOFTWARE, "buffer overflow");
    if (buffer->length + size > buffer->size) {
        buffer->pointer = svl_crealloc(buffer->pointer, buffer->size, buffer->size + size, sizeof(char));
        buffer->size += size;
    }
}

static char *
svl_buffer_line(svl_buffer_t *buffer) {
    char character, *line = NULL;
    size_t i;

    for (i = buffer->offset; i < buffer->length; i++) {
        character = ((char *)buffer->pointer)[i];
        if (isascii((int)character) && iscntrl((int)character) && !isspace((int)character)) /* ignore non-ascii characters */
            errx(EX_DATAERR, "invalid character");
        if (character == '\n') {
            ((char *)buffer->pointer)[i] = '\0';
            line = &((char *)buffer->pointer)[buffer->offset];
            buffer->offset = i + 1;
            break;
        }
    }
    return line;
}

static void
svl_buffer_compact(svl_buffer_t *buffer) {
    if (buffer->offset >= BUFSIZ) {
       memmove(buffer->pointer, (char *)buffer->pointer + buffer->offset, buffer->length - buffer->offset);
       buffer->length -= buffer->offset;
       buffer->offset = 0;
       memset((char *)buffer->pointer + buffer->length, 0, buffer->size - buffer->length);
    }
}

static void
svl_buffer_free(svl_buffer_t *buffer) {
    if (buffer == NULL)
        return;
    free(buffer->pointer);
    free(buffer);
}

static void
svl_url_parse(svl_url_t *url, const char *string) {
    if (sscanf(string, "%"SVL_QUOTE(NI_MAXSERV)"[0-9a-zA-Z+.-]://%"SVL_QUOTE(NI_MAXHOST)"[0-9a-zA-Z.-]:%"SVL_QUOTE(NI_MAXSERV)"[0-9]", url->scheme, url->host, url->port) < 2)
        (errno ? err : errx)(EX_DATAERR, "url failed");
    if (/*strcmp(url->scheme, "dns") != 0 &&*/
        strcmp(url->scheme, "http") != 0 && strcmp(url->scheme, "https") != 0)
        errx(EX_UNAVAILABLE, "scheme unsupported %s", url->scheme);
}

static void
svl_address_resolve(svl_address_t *address, svl_url_t *url) {
    const char *service = NULL;
    struct addrinfo hints, *addresses, *node;
    int descriptor, result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    if (strcmp(url->scheme, "dns") == 0) {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        service = "domain";
    }
    else if (strncmp(url->scheme, "http", 4) == 0) {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        service = "www";
    }
    if ((result = getaddrinfo(url->host, strlen(url->port) ? url->port : service, &hints, &addresses)) != SVL_SUCCESS)
        errx(EX_OSERR, "getaddrinfo failed %s", gai_strerror(result));
    for (node = addresses; node != NULL; node = addresses->ai_next) {
        if ((descriptor = socket(node->ai_family, node->ai_socktype, node->ai_protocol)) == SVL_ERROR)
            continue;
        if (connect(descriptor, node->ai_addr, node->ai_addrlen) == SVL_ERROR) {
            close(descriptor);
            continue;
        }
        address->family = node->ai_family;
        address->type = node->ai_socktype;
        address->protocol = node->ai_protocol;
        memmove(&address->storage, node->ai_addr, node->ai_addrlen);
        address->size = node->ai_addrlen;
        close(descriptor);
        break;
    }
    freeaddrinfo(addresses);
    if (node == NULL)
        errx(EX_NOHOST, "resolve failed");
}

static void
svl_file_setup(svl_file_t *file, const char *path) {
    file->path = path;
    file->descriptor = SVL_UNDEFINED;
    file->buffer = svl_calloc(1, sizeof(svl_buffer_t));
}

static void
svl_file_open(svl_file_t *file) {
    if ((file->descriptor = open(file->path, O_RDONLY)) == SVL_ERROR)
        errx(EX_IOERR, "open failed");
}

static ssize_t
svl_file_read(svl_file_t *file) {
    ssize_t result;

    svl_buffer_expand(file->buffer, BUFSIZ);
    result = read(file->descriptor, ((char *)file->buffer->pointer) + file->buffer->length, BUFSIZ);
    if (result == SVL_ERROR)
        err(EX_OSERR, "read failed");
    if (result > 0)
        file->buffer->length += result;
    return result;
}

static void
svl_file_close(svl_file_t *file) {
    if (file->descriptor != SVL_UNDEFINED)
        close(file->descriptor);
    file->descriptor = SVL_UNDEFINED;
}

static void
svl_file_free(svl_file_t *file) {
    if (file == NULL)
        return;
    svl_buffer_free(file->buffer);
    svl_file_close(file);
    free(file);
}

static void
svl_method_parse(svl_method_t *method, const char *name, const char *factor) {
    if (name != NULL &&
        strcmp(name, "fast") != 0 && strcmp(name, "multiply") != 0 &&
        strcmp(name, "peak") != 0 && strcmp(name, "score") != 0)
        errx(EX_UNAVAILABLE, "method unsupported %s", name);
    method->name = name;
    if (method->name != NULL && factor != NULL && 
        (strcmp(method->name, "fast") == 0 || sscanf(factor, "%hu", &method->factor) != 1))
        errx(EX_DATAERR, "factor failed");
}

static void
svl_request_setup(svl_request_t *request) {
    request->buffer = calloc(1, sizeof(svl_buffer_t));
}

static int
svl_request_timeout(svl_request_t *request) {
    if (request->start > 0 &&
        svl_timestamp_now() - request->start >= SVL_REQUEST_TIMEOUT)
        return SVL_TRUE;
    return SVL_FALSE;
}

static void
svl_request_link(svl_request_t *request_a, svl_request_t *request_b) {
    if (request_a != NULL)
        request_a->next = request_b;
    if (request_b != NULL)
        request_b->previous = request_a;
}

static void
svl_request_unlink(svl_request_t *request) {
    svl_request_link(request->previous, request->next);
    request->previous = NULL;
    request->next = NULL;
}

static int
svl_request_compare_timestamp(const void *pointer_a, const void *pointer_b) {
    const svl_request_t *request_a = *(const svl_request_t * const *)pointer_a;
    const svl_request_t *request_b = *(const svl_request_t * const *)pointer_b;

    return svl_timestamp_compare(&request_a->timestamp, &request_b->timestamp);
}

static int
svl_request_compare_wait(const void *pointer_a, const void *pointer_b) {
    const svl_request_t *request_a = *(const svl_request_t * const *)pointer_a;
    const svl_request_t *request_b = *(const svl_request_t * const *)pointer_b;

    return svl_timestamp_compare(&request_a->wait, &request_b->wait);
}

static double
svl_request_median_wait(svl_request_t **requests, size_t length) {
    qsort(requests, length, sizeof(svl_request_t *), &svl_request_compare_wait);
    if (length % 2 != 0)
        return requests[length / 2]->wait;
    else
        return (requests[length / 2 - 1]->wait + requests[length / 2]->wait) / 2.0;
}

static void
svl_request_free(svl_request_t *request) {
    if (request == NULL)
        return;
    free(request->key);
    svl_buffer_free(request->buffer);
    free(request);
}

static void
svl_request_dns_parse(svl_request_dns_t *request, svl_url_t *url, char *line) {
    /*
     * bind syslog:
     * Oct 19 13:29:27 hostname named[10720]: client 127.0.0.1#38218: query: renard.cs.vu.nl IN A +
     *
     * bind channel-to-file:
     * 19-Oct-2010 13:34:01.485 client 127.0.0.1#26332: query: heise.de IN A +
     * 19-Oct-2010 13:34:43.375 queries: info: client 127.0.0.1#8677: query: google.de IN A +
     */
    (void)request; /* silence compiler warnings until implemented */
    (void)url;
    (void)line;
    (void)svl_timestamp_dns;
}

static void
svl_request_dns_response(svl_request_dns_t *request, svl_statistic_dns_t *statistic, svl_buffer_t *buffer) {
    /* todo */
    (void)request; /* silence compiler warnings until implemented */
    (void)statistic;
    (void)buffer;
    /* 
     * this function should take care of buffer->offset and move it forward 
     * to clarify which part of the read buffer is already done
     * 
     * http does this often implicit by svl_buffer_line()
     * dns may require similar e.g. svl_buffer_get_dns_packet()
     */
}

static void
svl_request_http_parse(svl_request_http_t *request, svl_url_t *url, char *line) {
    const char *idempotent[] = { "DELETE", "GET", "HEAD", "OPTIONS", "PUT", "TRACE", NULL };
    const char *host, *user, *date = NULL, *method = NULL, *path, *version;
    const char *status = NULL, *bytes, *agent = NULL; /* agent is optional */
    unsigned int i;

    if ((host = strsep(&line, " ")) == NULL || strlen(host) == 0)
        errx(EX_DATAERR, "host failed");
    if (strsep(&line, " ") == NULL) /* skip ident */
        errx(EX_DATAERR, "ident failed");
    if ((user = strsep(&line, " ")) == NULL || strlen(user) == 0)
        errx(EX_DATAERR, "user failed");
    if (strsep(&line, "[") == NULL || /* skip date start */
        (date = strsep(&line, "]")) == NULL || strlen(date) == 0)
        errx(EX_DATAERR, "date failed");
    if (strsep(&line, "\"") == NULL || /* skip request start */
        (method = strsep(&line, " ")) == NULL || strlen(method) == 0)
        errx(EX_DATAERR, "method failed");
    if ((path = strsep(&line, " ")) == NULL || strlen(path) == 0)
        errx(EX_DATAERR, "path failed");
    if ((version = strsep(&line, "\"")) == NULL || strlen(version) == 0)
        errx(EX_DATAERR, "version failed");
    if (strsep(&line, " ") == NULL || /* skip space before status */
        (status = strsep(&line, " ")) == NULL || strlen(status) == 0)
        errx(EX_DATAERR, "status failed");
    if ((bytes = strsep(&line, " ")) == NULL || strlen(bytes) == 0)
        errx(EX_DATAERR, "bytes failed");
    if (line != NULL && strlen(line) > 0) { /* check if combined log */
        if (strsep(&line, "\"") == NULL || strsep(&line, "\"") == NULL) /* skip referrer */
            errx(EX_DATAERR, "referrer failed");
        if (strsep(&line, "\"") == NULL || /* skip agent start */
            (agent = strsep(&line, "\"")) == NULL || strlen(agent) == 0)
            errx(EX_DATAERR, "agent failed");
    }
    if (agent == NULL || strcmp(agent, "-") == 0)
        agent = "servload/"SVL_VERSION;
    svl_buffer_append(((svl_request_t *)request)->buffer, method, strlen(method));
    svl_buffer_append(((svl_request_t *)request)->buffer, " ", 1);
    svl_buffer_append(((svl_request_t *)request)->buffer, path, strlen(path));
    svl_buffer_append(((svl_request_t *)request)->buffer, " ", 1);
    svl_buffer_append(((svl_request_t *)request)->buffer, version, strlen(version));
    svl_buffer_append(((svl_request_t *)request)->buffer, " ", 1);
    svl_buffer_append(((svl_request_t *)request)->buffer, "\r\nHost: ", 8);
    svl_buffer_append(((svl_request_t *)request)->buffer, url->host, strlen(url->host));
    svl_buffer_append(((svl_request_t *)request)->buffer, "\r\nUser-Agent: ", 14);
    svl_buffer_append(((svl_request_t *)request)->buffer, agent, strlen(agent));
    svl_buffer_append(((svl_request_t *)request)->buffer, "\r\n", 2); /* final crlf follows in sequence prepare */
    ((svl_request_t *)request)->timestamp = svl_timestamp_http(date);
    if (strcasecmp(version, "HTTP/1.1") == 0)
        for (i = 0; idempotent[i] != NULL; i++)
            if (strcasecmp(method, idempotent[i]) == 0)
                ((svl_request_t *)request)->flags |= SVL_FLAG_PIPELINE;
    svl_asprintf(&((svl_request_t *)request)->key, "%s%s", 
                 (strcmp(user, "-") == 0) ? host : user, agent);
    if (strcmp(bytes, "-") != 0 && sscanf(bytes, "%lu", &request->bytes) != 1)
        errx(EX_DATAERR, "bytes failed");
    if (sscanf(status, "%u", &request->status) != 1)
        errx(EX_DATAERR, "status failed");
}

static void
svl_request_http_response(svl_request_http_t *request, svl_statistic_http_t *statistic, svl_buffer_t *buffer) {
    if (request->state == SVL_HTTP_STATUS || request->state == SVL_HTTP_CONTINUE)
        svl_request_http_status(request, statistic, buffer);
    if (request->state == SVL_HTTP_HEADER)
        svl_request_http_header(request, buffer);
    if (request->state == SVL_HTTP_BODY)
        svl_request_http_body(request, buffer);
}

static void
svl_request_http_status(svl_request_http_t *request, svl_statistic_http_t *statistic, svl_buffer_t *buffer) {
    unsigned int status;
    double version;
    char *line;

    while ((line = svl_buffer_line(buffer)) != NULL) {
        if (request->state == SVL_HTTP_STATUS) {
            if (sscanf(line, "HTTP/%lf %u", &version, &status) != 2)
                errx(EX_DATAERR, "status failed");
            if (status == 100) {
                request->status = SVL_HTTP_CONTINUE;
                continue;
            }
            if (version < 1.1)
                ((svl_request_t *)request)->flags |= SVL_FLAG_CLOSE;
            if (status == 101 || status == 204 || status == 304)
                request->body = SVL_HTTP_BODY_EMPTY;
            if (status != request->status)
                statistic->mismatch++;
            if (status != request->status && status == 404)
                statistic->not_found++;
            if (status != request->status && status >= 500)
                statistic->server_error++;
            request->state = SVL_HTTP_HEADER;
            break;

        }
        else if (request->state == SVL_HTTP_CONTINUE && 
                 strlen(svl_strtrim(line)) == 0) /* skip continue header */
            request->state = SVL_HTTP_STATUS;
    }
    svl_buffer_compact(buffer);
}

static void
svl_request_http_header(svl_request_http_t *request, svl_buffer_t *buffer) {
    char *line;

    while ((line = svl_buffer_line(buffer)) != NULL) {
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            if (strcasestr(line + 18, "Chunked") == NULL)
                errx(EX_UNAVAILABLE, "transfer unsupported");
            request->response = SVL_UNDEFINED; /* size_t maximum */
            request->body = SVL_HTTP_BODY_CHUNK;
        }
        else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            if (sscanf(line + 15, "%lu", &request->response) != 1)
                errx(EX_DATAERR, "content failed");
            request->body = SVL_HTTP_BODY_CONTENT;
        }
        else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (strcasestr(line + 11, "Close") == NULL)
                errx(EX_DATAERR, "connection failed");
            ((svl_request_t *)request)->flags |= SVL_FLAG_CLOSE;
        }
        else if (strlen(svl_strtrim(line)) == 0) {
            if (request->body == SVL_HTTP_BODY_EMPTY)
                ((svl_request_t *)request)->flags |= SVL_FLAG_DONE;
            else if (request->body == SVL_HTTP_BODY_EOF)
                ((svl_request_t *)request)->flags |= SVL_FLAG_EOF;
            request->state = SVL_HTTP_BODY;
            break;
        }        
    }
    svl_buffer_compact(buffer);
}

static void
svl_request_http_body(svl_request_http_t *request, svl_buffer_t *buffer) {
    size_t bytes;
    char *line;
    
    if (request->body == SVL_HTTP_BODY_CHUNK) {
        while (SVL_TRUE) { /* iterate over chunks */
            if (request->response == (size_t)SVL_UNDEFINED) {
                if ((line = svl_buffer_line(buffer)) == NULL)
                    break; /* receive more */
                if (sscanf(line, "%lx", &request->response) != 1 || request->response == (size_t)SVL_UNDEFINED) /* only zero till size_t maximum - 1 is valid */
                    errx(EX_DATAERR, "chunk failed");
                if (request->response > 0) /* final crlf after each chunk is not part of chunk size */
                    request->response += strlen("\r\n");
            }
            else if (request->response > 0) {
                bytes = buffer->length - buffer->offset;
                bytes = (bytes > request->response) ? request->response : bytes; /* limit required bytes from pipeline buffer */              
                buffer->offset += bytes;
                if ((request->response -= bytes) > 0)
                    break; /* receive more */
                request->response = SVL_UNDEFINED; /* size_t maximum */                    
            }
            else if (request->response == 0) {
                if((line = svl_buffer_line(buffer)) == NULL)
                    break; /* receive more */
                if (strlen(svl_strtrim(line)) == 0) { /* skip footer */
                    ((svl_request_t *)request)->flags |= SVL_FLAG_DONE;
                    break; /* request done */
                }                
            }
        }
    }
    else if (request->body == SVL_HTTP_BODY_CONTENT) {
        bytes = buffer->length - buffer->offset;
        bytes = (bytes > request->response) ? request->response : bytes; /* limit required bytes from pipeline buffer */
        buffer->offset += bytes;
        if ((request->response -= bytes) == 0)
            ((svl_request_t *)request)->flags |= SVL_FLAG_DONE;
    }
    /* todo: else if (request->body == SVL_HTTP_BODY_MULTIPART) */
    else if (request->body == SVL_HTTP_BODY_EOF)
        buffer->offset = buffer->length;
    svl_buffer_compact(buffer);
}

static int
svl_request_http_compare_bytes(const void *pointer_a, const void *pointer_b) {
    const svl_request_http_t *request_a = *(const svl_request_http_t * const *)pointer_a;
    const svl_request_http_t *request_b = *(const svl_request_http_t * const *)pointer_b;

    return (request_a->bytes > request_b->bytes) - (request_a->bytes < request_b->bytes);
}

static double
svl_request_http_median_bytes(svl_request_http_t **requests, size_t length) {
    qsort(requests, length, sizeof(svl_request_http_t *), svl_request_http_compare_bytes);
    if (length % 2 != 0)
        return requests[length / 2]->bytes;
    else
        return (requests[length / 2 - 1]->bytes + requests[length / 2]->bytes) / 2.0;
}

static int
svl_session_compare_length(const void *pointer_a, const void *pointer_b) {
    const svl_session_t *session_a = *(const svl_session_t * const *)pointer_a;
    const svl_session_t *session_b = *(const svl_session_t * const *)pointer_b;

    return (session_a->length > session_b->length) - (session_a->length < session_b->length);
}

static int
svl_session_compare_duration(const void *pointer_a, const void *pointer_b) {
    const svl_session_t *session_a = *(const svl_session_t * const *)pointer_a;
    const svl_session_t *session_b = *(const svl_session_t * const *)pointer_b;

    return svl_timestamp_compare(&session_a->duration, &session_b->duration);
}

static int
svl_session_compare_thinktime(const void *pointer_a, const void *pointer_b) {
    const svl_session_t *session_a = *(const svl_session_t * const *)pointer_a;
    const svl_session_t *session_b = *(const svl_session_t * const *)pointer_b;

    return svl_timestamp_compare(&session_a->thinktime, &session_b->thinktime);
}

static int
svl_session_compare_bytes(const void *pointer_a, const void *pointer_b) {
    const svl_session_t *session_a = *(const svl_session_t * const *)pointer_a;
    const svl_session_t *session_b = *(const svl_session_t * const *)pointer_b;

    return (session_a->bytes > session_b->bytes) - (session_a->bytes < session_b->bytes);
}

static double
svl_session_median_length(svl_session_t **sessions, size_t length) {
    qsort(sessions, length, sizeof(svl_session_t *), svl_session_compare_length);
    if (length % 2 != 0)
        return sessions[length / 2]->length;
    else
        return (sessions[length / 2 - 1]->length + sessions[length / 2]->length) / 2.0;
}

static double
svl_session_median_duration(svl_session_t **sessions, size_t length) {
    qsort(sessions, length, sizeof(svl_session_t *), svl_session_compare_duration);
    if (length % 2 != 0)
        return sessions[length / 2]->duration;
    else
        return (sessions[length / 2 - 1]->duration + sessions[length / 2]->duration) / 2.0;
}

static double
svl_session_median_thinktime(svl_session_t **sessions, size_t length) {
    qsort(sessions, length, sizeof(svl_session_t *), svl_session_compare_thinktime);
    if (length % 2 != 0)
        return sessions[length / 2]->thinktime;
    else
        return (sessions[length / 2 - 1]->thinktime + sessions[length / 2]->thinktime) / 2.0;
}

static double
svl_session_median_bytes(svl_session_t **sessions, size_t length) {
    qsort(sessions, length, sizeof(svl_session_t *), svl_session_compare_bytes);
    if (length % 2 != 0)
        return sessions[length / 2]->bytes;
    else
        return (sessions[length / 2 - 1]->bytes + sessions[length / 2]->bytes) / 2.0;
}

static size_t
svl_hash(const char *key) { /* bernstein hash function */
    size_t hash = 0;

    while(*key != '\0')
        hash = SVL_HASH * hash + *key++; /* bernstein hash multiplier: 33 */
    return hash;
}

static void
svl_hash_setup(svl_hash_t *table, size_t buckets) {
    table->sessions = svl_calloc(buckets, sizeof(svl_session_t *));
    table->buckets = buckets;
}

static svl_session_t *
svl_hash_lookup(svl_hash_t *table, const char *key) {
    svl_session_t *session;
    size_t hash = svl_hash(key) % table->buckets;

    for (session = table->sessions[hash]; session != NULL; session = session->next)
        if(strcmp(session->key, key) == 0)
            return session;
    return NULL;
}

static svl_session_t *
svl_hash_insert(svl_hash_t *table, const char *key) {
    svl_session_t *session;
    size_t hash = svl_hash(key) % table->buckets;

    if (svl_hash_lookup(table, key) != NULL)
        errx(EX_SOFTWARE, "hash insert");
    session = svl_calloc(1, sizeof(svl_session_t));
    session->key = key; /* no string key duplication */
    session->id = table->length++;
    session->next = table->sessions[hash];
    table->sessions[hash] = session;
    return session;
}

static svl_session_t *
svl_hash_next(svl_hash_t *table, svl_session_t *session) {
    size_t hash = 0;
    size_t i;

    if (session != NULL && session->next != NULL)
        return session->next;
    if (session != NULL)
        hash = svl_hash(session->key) % table->buckets + 1;
    for (i = hash; i < table->buckets; i++)
        if (table->sessions[i] != NULL)
            return table->sessions[i];
    return NULL;
}

static void
svl_hash_free(svl_hash_t *table) {
    svl_session_t *session;
    size_t i;

    if (table == NULL)
        return;
    for (i = 0; i < table->buckets; i++) {
        while ((session = table->sessions[i]) != NULL) {
            table->sessions[i] = session->next;
            free(session);
        }
    }
    free(table->sessions);
    free(table);
}

static void
svl_histogram_setup(svl_histogram_t *histogram, size_t length) {
    histogram->frequency = svl_calloc(length, sizeof(unsigned long));
    histogram->clones = svl_calloc(length, sizeof(unsigned long));
    histogram->length = length;
}

static void
svl_histogram_frequency(svl_histogram_t *histogram, svl_request_t **requests, size_t length) {
    unsigned long *frequency = histogram->frequency, *clones = histogram->clones;
    size_t i;

    for (i = 0; i < histogram->length; i++)
        frequency[i] = clones[i] = 0;
    for (i = 0; i < length; i++) {
        frequency[svl_round(requests[i]->timestamp - requests[0]->timestamp)]++;
        if (requests[i]->flags & SVL_FLAG_CLONE)
            clones[svl_round(requests[i]->timestamp - requests[0]->timestamp)]++;
    }
    histogram->maximum = 0;
    for (i = 0; i < histogram->length; i++)
        if (frequency[i] > histogram->maximum)
            histogram->maximum = frequency[i];
}

static void
svl_histogram_plot(svl_histogram_t *histogram) {
    unsigned long *frequency = histogram->frequency, *clones = histogram->clones;
    const char *title = "Requests per second";
    struct winsize window = { 0, 0, 0, 0 };
    double factor_x, factor_y;
    size_t tic, i, j;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == SVL_ERROR)
        err(EX_OSERR, "ioctl failed");
    if (window.ws_col < 80 || window.ws_row < 24) {
        warnx("small window: no plot");
        return;
    }
    printf(SVL_ANSI_SF, window.ws_row - svl_round(SVL_MARGIN / 2.0));
    factor_x = histogram->length / (double)(window.ws_col - 2 * SVL_MARGIN);
    factor_y = histogram->maximum / (double)(window.ws_row - 2 * SVL_MARGIN);    
    for (i = 0; i < histogram->length; i++) { /* scale y values */
        frequency[i] = svl_round(frequency[i] / factor_y);
        clones[i] = svl_round(clones[i] / factor_y);
    }
    printf(SVL_ANSI_CM"%s", svl_round(SVL_MARGIN / 2.0), /* center title */
           svl_round((window.ws_col / 2.0) - (strlen(title) / 2.0)), title);
    for (i = 0; i < histogram->length; i++) {
        for (j = 0; j < frequency[i]; j++)
            printf(SVL_ANSI_CM"|", 
                   (window.ws_row - SVL_MARGIN - frequency[i] + j),
                   SVL_MARGIN + svl_round(i / factor_x));
        for (j = 0; j < clones[i]; j++)
            printf(SVL_ANSI_CM".", 
                   (window.ws_row - SVL_MARGIN - frequency[i] + j), 
                   SVL_MARGIN + svl_round(i / factor_x));
    }
    tic = svl_round(histogram->maximum / (double)(SVL_TIC - 1));
    for (i = 1; i < SVL_TIC && i <= histogram->maximum; i++) /* y tics */
       printf(SVL_ANSI_CM"%lu", window.ws_row - SVL_MARGIN - svl_round((tic * i) / factor_y), 1UL, tic * i);
    tic = svl_round(histogram->length / (double)SVL_TIC);
    for (i = 0; i < histogram->length; i++) /* x axis */
       printf(SVL_ANSI_CM"-", (unsigned long)(window.ws_row - SVL_MARGIN), SVL_MARGIN + svl_round(i / factor_x));
    for (i = 0; i <= SVL_TIC && i <= histogram->length; i++) { /* x tics */
       printf(SVL_ANSI_CM"+", (unsigned long)(window.ws_row - SVL_MARGIN), SVL_MARGIN + svl_round((i * tic)/factor_x));
       printf(SVL_ANSI_CM"%lu", (unsigned long)(window.ws_row - SVL_MARGIN + 1), SVL_MARGIN + svl_round((i * tic)/factor_x), tic * i);
    }
    printf("\n");
}

static void
svl_histogram_free(svl_histogram_t *histogram) {
    if (histogram == NULL)
        return;
    free(histogram->frequency);
    free(histogram->clones);
    free(histogram);
}

static void
svl_sequence_setup(svl_sequence_t *sequence) {
    sequence->sessions = svl_calloc(1, sizeof(svl_hash_t));
    sequence->histogram = svl_calloc(1, sizeof(svl_histogram_t));
}

static void
svl_sequence_load(svl_sequence_t *sequence, svl_url_t *url, svl_file_t *file) {
    svl_request_t *request;
    char *line;

    svl_file_open(file);
    while (svl_file_read(file) > 0) {
        while ((line = svl_buffer_line(file->buffer)) != NULL) {
            line = svl_strtrim(line);
            request = svl_sequence_append(sequence, url);
            svl_request_setup(request);
            if (strcmp(url->scheme, "dns") == 0)
                svl_request_dns_parse((svl_request_dns_t *)request, url, line);
            else if (strncmp(url->scheme, "http", 4) == 0)
                svl_request_http_parse((svl_request_http_t *)request, url, line);            
            if (sequence->length % SVL_STATUS == 0)
                svl_sequence_status(sequence, "load %lu requests", sequence->length);
        }
        svl_buffer_compact(file->buffer);
    }
    if (file->buffer->offset != file->buffer->length)
        err(EX_DATAERR, "incomplete file");
    svl_file_close(file);
}

static svl_request_t *
svl_sequence_append(svl_sequence_t *sequence, svl_url_t *url) {
    if (sequence->length == SIZE_T_MAX)
        errx(EX_SOFTWARE, "sequence overflow");
    sequence->requests = svl_crealloc(sequence->requests, sequence->length, sequence->length + 1, sizeof(svl_request_t *));
    if (strcmp(url->scheme, "dns") == 0)
        sequence->requests[sequence->length] = svl_calloc(1, sizeof(svl_request_dns_t));
    else if (strncmp(url->scheme, "http", 4) == 0)
        sequence->requests[sequence->length] = svl_calloc(1, sizeof(svl_request_http_t));
    return sequence->requests[sequence->length++];
}

static void
svl_sequence_analyse(svl_sequence_t *sequence) {
    svl_request_t **requests = sequence->requests;
    svl_session_t *session;
    size_t i;

    if (sequence->length == 0)
        errx(EX_SOFTWARE, "zero requests");
    svl_sequence_status(sequence, "analyse");
    qsort(requests, sequence->length, sizeof(svl_request_t *), svl_request_compare_timestamp);
    sequence->duration = requests[sequence->length - 1]->timestamp - requests[0]->timestamp;
    svl_hash_setup(sequence->sessions, sequence->length); /* tradeoff buckets guess */
    for (i = 0; i < sequence->length; i++) {
        if ((session = svl_hash_lookup(sequence->sessions, requests[i]->key)) == NULL)
            session = svl_hash_insert(sequence->sessions, requests[i]->key); /* new session */
        session->length++;
    }
    svl_histogram_setup(sequence->histogram, svl_round(sequence->duration) + 1);
}

static void
svl_sequence_modify(svl_sequence_t* sequence, svl_url_t *url, svl_method_t *method) {
    /* fast method is handled in sequence prepare below */
    if (strcmp(method->name, "multiply") == 0)
        svl_sequence_multiply(sequence, url, method->factor);
    else if (strcmp(method->name, "peak") == 0)
        svl_sequence_peak(sequence, url, method->factor);
    else if (strcmp(method->name, "score") == 0)
        svl_sequence_score(sequence, url, method->factor);
}

static void
svl_sequence_multiply(svl_sequence_t *sequence, svl_url_t *url, unsigned int factor) {
    size_t length = sequence->length, i;
    unsigned int j;

    svl_sequence_status(sequence, "modify multiply");
    for (i = 0; i < length; i++)
        for (j = 1; j < factor; j++)
            svl_sequence_clone(sequence, url, i, j);
}

static void
svl_sequence_peak(svl_sequence_t *sequence, svl_url_t *url, unsigned int factor) {
    svl_histogram_t *histogram = sequence->histogram;
    double median;
    size_t i, length = sequence->length;
    unsigned long frequency, j;

    svl_sequence_status(sequence, "modify peak");
    svl_histogram_frequency(histogram, sequence->requests, length);
    median = svl_ulong_median(histogram->frequency, histogram->length);
    svl_histogram_frequency(histogram, sequence->requests, length); /* order */
    for (i = 0; i < length; i++) {
        frequency = histogram->frequency[svl_round(sequence->requests[i]->timestamp - sequence->requests[0]->timestamp)];
        for (j = 1; j < factor && frequency >= median; j++)
            svl_sequence_clone(sequence, url, i, j);
    }
}

static void
svl_sequence_score(svl_sequence_t *sequence, svl_url_t *url, unsigned int factor) {
    svl_session_t **sessions = svl_calloc(sequence->sessions->length, sizeof(svl_session_t));
    svl_session_t *session = NULL;    
    double median_length = 0, median_duration = 0, median_thinktime = 0, median_bytes = 0;
    double aad_length = 0, aad_duration = 0, aad_thinktime = 0, aad_bytes = 0;
    size_t length = sequence->length, i = 0;
    unsigned int j;

    svl_sequence_status(sequence, "modify score");
    if (sequence->sessions->length < 3)
        warnx("few sessions: score may pointless");
    svl_sequence_metric(sequence, url);
    while ((session = svl_hash_next(sequence->sessions, session)) != NULL)
        sessions[i++] = session;
    median_length = svl_session_median_length(sessions, sequence->sessions->length);
    median_duration = svl_session_median_duration(sessions, sequence->sessions->length);
    median_thinktime = svl_session_median_thinktime(sessions, sequence->sessions->length);
    if (strncmp(url->scheme, "http", 4) == 0)
        median_bytes = svl_session_median_bytes(sessions, sequence->sessions->length);
    for (i = 0; i < sequence->sessions->length; i++) { /* average absolute deviation from median */
        aad_length += fabs(sessions[i]->length - median_length) / sequence->sessions->length;
        aad_duration += fabs(sessions[i]->duration - median_duration) / sequence->sessions->length;
        aad_thinktime += fabs(sessions[i]->thinktime - median_thinktime) / sequence->sessions->length;
        if (strncmp(url->scheme, "http", 4) == 0)
            aad_bytes += fabs(sessions[i]->bytes - median_bytes) / sequence->sessions->length;
    }
    for (i = 0; i < sequence->sessions->length; i++) { /* normalize score to 0 ... 25 */
        sessions[i]->score = svl_sequence_normalize(url, fabs(sessions[i]->length - median_length), aad_length);
        sessions[i]->score += svl_sequence_normalize(url, fabs(sessions[i]->duration - median_duration), aad_duration);
        sessions[i]->score += svl_sequence_normalize(url, fabs(sessions[i]->thinktime - median_thinktime), aad_thinktime);
        if (strncmp(url->scheme, "http", 4) == 0)
            sessions[i]->score += svl_sequence_normalize(url, fabs(sessions[i]->bytes - median_bytes), aad_bytes);
    }
    free(sessions);
    while ((session = svl_hash_next(sequence->sessions, session)) != NULL)
        for (i = 0; i < length && session->score > SVL_SCORE; i++)
            for (j = 1; j < factor && strcmp(session->key, sequence->requests[i]->key) == 0; j++)
                svl_sequence_clone(sequence, url, i, j);
}

static void
svl_sequence_metric(svl_sequence_t *sequence, svl_url_t *url) {
    svl_request_t **requests;
    svl_session_t *session = NULL;
    size_t i, j;

    while ((session = svl_hash_next(sequence->sessions, session)) != NULL) {
        requests = svl_calloc(session->length, sizeof(svl_request_t *));
        for (i = 0, j = 0; i < sequence->length && j < session->length; i++)
            if (strcmp(session->key, sequence->requests[i]->key) == 0)
                requests[j++] = sequence->requests[i];
        if (session->length > 1) {
            session->duration = requests[session->length - 1]->timestamp - requests[0]->timestamp;
            requests[0]->wait = 0;
            for (i = 1; i < session->length; i++)
                requests[i]->wait = requests[i]->timestamp - requests[i - 1]->timestamp;
            session->thinktime = svl_request_median_wait(requests, session->length);
        }
        if (strncmp(url->scheme, "http", 4) == 0)
            session->bytes = svl_request_http_median_bytes((svl_request_http_t **)requests, session->length);
        free(requests);
    }
}

static unsigned short
svl_sequence_normalize(svl_url_t *url, double value, double aad) { /* normalize to maximum score of 100 for all metrics */
    double maximum = (strncmp(url->scheme, "http", 4) == 0) ? 100 / 4 : 100 / 3; /* http has four metrics */

    if (aad == 0) /* catch division by zero */
        return value ? 0 : svl_round(maximum);
    return value > aad ? 0 : svl_round(maximum * (1 - value / aad));
}

static void
svl_sequence_clone(svl_sequence_t *sequence, svl_url_t *url, size_t position, unsigned int id) {
    svl_request_t *request = svl_sequence_append(sequence, url);
    svl_request_t *source = sequence->requests[position];
    svl_session_t *session;

    if (strcmp(url->scheme, "dns") == 0)
        memmove(request, source, sizeof(svl_request_dns_t));
    else if (strncmp(url->scheme, "http", 4) == 0)
        memmove(request, source, sizeof(svl_request_http_t));
    svl_request_setup(request);    
    svl_buffer_append(request->buffer, source->buffer->pointer, source->buffer->length);
    svl_asprintf(&request->key, "%s%u", source->key, id);
    if ((session = svl_hash_lookup(sequence->sessions, request->key)) == NULL)
        session = svl_hash_insert(sequence->sessions, request->key); /* new session */
    session->length++;
    request->flags |= SVL_FLAG_CLONE;
}

static void
svl_sequence_prepare(svl_sequence_t *sequence, svl_url_t *url, svl_method_t *method) {
    svl_request_t **requests = sequence->requests;
    svl_session_t *session;
    size_t i;

    svl_sequence_status(sequence, "prepare");
    qsort(requests, sequence->length, sizeof(svl_request_t *), svl_request_compare_timestamp);
    sequence->duration = requests[sequence->length - 1]->timestamp - requests[0]->timestamp;
    for (i = 1; i < sequence->length; i++)
        if (method->name == NULL || strcmp(method->name, "fast") != 0)
            requests[i]->wait = requests[i]->timestamp - requests[i - 1]->timestamp;
    for (i = sequence->length; i-- > 0; ) { /* reverse loop */
        session = svl_hash_lookup(sequence->sessions, requests[i]->key);
        if (session->last == SVL_FALSE) {
            requests[i]->flags &= ~SVL_FLAG_PIPELINE; /* stop pipeline after last request in session */
            session->last = SVL_TRUE;
        }
    }
    for (i = 0; i < sequence->length && strncmp(url->scheme, "http", 4) == 0; i++) {
        if (!(requests[i]->flags & SVL_FLAG_PIPELINE))
            svl_buffer_append(requests[i]->buffer, "Connection: close\r\n", 19);
        svl_buffer_append(requests[i]->buffer, "\r\n", 2);
    }
}

static void
svl_sequence_plot(svl_sequence_t *sequence) {
    svl_histogram_frequency(sequence->histogram, sequence->requests, sequence->length);
    svl_histogram_plot(sequence->histogram);
}

static void
svl_sequence_status(svl_sequence_t *sequence, const char *format, ...) {
    va_list arguments;

    if (sequence->length < SVL_STATUS)
        return;
    printf(SVL_ANSI_RC);
    printf(SVL_ANSI_CE"sequence: ");
    va_start(arguments, format);
    vprintf(format, arguments);
    va_end(arguments);
    fflush(stdout);
}

static void
svl_sequence_free(svl_sequence_t *sequence) {
    size_t i;

    if (sequence == NULL)
        return;
    svl_histogram_free(sequence->histogram);
    svl_hash_free(sequence->sessions);
    for (i = 0; i < sequence->length; i++)
        svl_request_free(sequence->requests[i]);
    free(sequence->requests);
    free(sequence);
}

static void
svl_queue_push(svl_queue_t *queue, svl_request_t *request) {
    svl_request_link(queue->tail, request);
    if (queue->head == NULL)
        queue->head = request;
    queue->tail = request;
}

static svl_request_t *
svl_queue_peek(svl_queue_t *queue) {
    return queue->head;
}

static svl_request_t *
svl_queue_pop(svl_queue_t *queue) {
    svl_request_t *request = queue->head;

    if (request == NULL)
        return request;
    queue->head = request->next;
    if (queue->tail == request)
        queue->tail = NULL;
    svl_request_unlink(request);
    return request;
}

static void
svl_connection_setup(svl_connection_t *connection, struct pollfd *descriptor) {
    connection->descriptor = descriptor;
    connection->write = svl_calloc(1, sizeof(svl_queue_t));
    connection->read = svl_calloc(1, sizeof(svl_queue_t));
    connection->buffer = svl_calloc(1, sizeof(svl_buffer_t));
}

static void
svl_connection_open(svl_connection_t *connection, svl_address_t *address, SSL_CTX *ssl_context) {
    struct pollfd *descriptor = connection->descriptor;
    int result, error, argument = 1, option = 1;

    if (descriptor->fd == SVL_UNDEFINED) {
        connection->open = svl_timestamp_now();
        descriptor->fd = socket(address->family, address->type, address->protocol);
        if (descriptor->fd == SVL_ERROR)
            errx(EX_OSERR, "socket failed");
        if (ioctl(descriptor->fd, FIONBIO, &argument) == SVL_ERROR)
            errx(EX_OSERR, "ioctl failed");
        if (address->protocol == IPPROTO_TCP &&
            setsockopt(descriptor->fd, IPPROTO_TCP, TCP_NODELAY, &option, (socklen_t) sizeof(option)) == SVL_ERROR)
            errx(EX_OSERR, "setsockopt failed");
        if (connect(descriptor->fd, (struct sockaddr *)&address->storage, address->size) == SVL_ERROR &&
            errno != EINTR && errno != EINPROGRESS)
            errx(EX_OSERR, "connect failed");
        if (ssl_context != NULL) {
            if ((connection->ssl = SSL_new(ssl_context)) == NULL)
                errx(EX_SOFTWARE, "ssl_new failed %s", ERR_error_string(ERR_get_error(), NULL));
            if (SSL_set_fd(connection->ssl, descriptor->fd) != SVL_TRUE)
                errx(EX_SOFTWARE, "ssl_set_fd failed %s", ERR_error_string(ERR_get_error(), NULL));
            if ((result = SSL_connect(connection->ssl)) != SVL_TRUE) {
                error = SSL_get_error(connection->ssl, result);
                if (error != SSL_ERROR_SYSCALL ||
                   (error == SSL_ERROR_SYSCALL && errno != EINTR && errno != EINPROGRESS))
                    errx(EX_OSERR, "ssl_connect failed %s", ERR_error_string((unsigned int)error, NULL));
            }
        }
    }
    if (descriptor->events == 0)
        descriptor->events = (POLLOUT | POLLWRBAND);
}

static void
svl_connection_write(svl_connection_t *connection, svl_statistic_t *statistic) {
    svl_request_t *request;
    ssize_t result;

    if (connection->open != 0)
        svl_statistic_connect(statistic, svl_timestamp_now() - connection->open);
    connection->open = 0;
    while ((request = svl_queue_peek(connection->write)) != NULL) {
        if (request->start <= 0)
            request->start = svl_timestamp_now();
        if (connection->ssl == NULL)
            result = write(connection->descriptor->fd,
                           (char *)request->buffer->pointer + request->buffer->offset,
                           request->buffer->length - request->buffer->offset);
        else
            result = SSL_write(connection->ssl, /* todo: handle result == 0 error case and call SSL_get_error() */
                               (char *)request->buffer->pointer + request->buffer->offset,
                               request->buffer->length - request->buffer->offset);
        if (result == SVL_ERROR) {
            svl_connection_error(connection, statistic, errno);
            return;
        }
        request->buffer->offset += result;
        statistic->bytes += result;
        if (request->buffer->offset != request->buffer->length)
            return;
        svl_queue_push(connection->read, svl_queue_pop(connection->write));
        if (!(request->flags & SVL_FLAG_PIPELINE))
            break;
    }
    connection->descriptor->events = (POLLIN | POLLPRI);
}

static void
svl_connection_read(svl_connection_t *connection, svl_statistic_t *statistic, svl_url_t *url) {
    svl_request_t *request;
    ssize_t result;

    svl_buffer_expand(connection->buffer, BUFSIZ);
    if (connection->ssl == NULL)
        result = read(connection->descriptor->fd,
                      (char *)connection->buffer->pointer + connection->buffer->length, BUFSIZ);
    else
        result = SSL_read(connection->ssl, /* todo: handle result == 0 error case and call SSL_get_error() */
                          (char *)connection->buffer->pointer + connection->buffer->length, BUFSIZ);
    if (result == SVL_ERROR) {
        svl_connection_error(connection, statistic, errno);
        return;
    }
    connection->buffer->length += result;
    statistic->bytes += result;
    while ((request = svl_queue_peek(connection->read)) != NULL) {
        if (result == 0 && !(request->flags & SVL_FLAG_EOF)) {
            svl_connection_error(connection, statistic, ECONNRESET);
            return;
        }
        if (result == 0 && request->flags & SVL_FLAG_EOF)
            request->flags |= SVL_FLAG_DONE;
        if (request->response <= 0)
            request->response = svl_timestamp_now() - request->start;
        if (svl_request_timeout(request) == SVL_TRUE) {
            while (svl_queue_pop(connection->read) != NULL) {
                statistic->timeout++;
                statistic->error++;
            }
            svl_connection_close(connection);
            return;
        }
        if (strcmp(url->scheme, "dns") == 0)
            svl_request_dns_response((svl_request_dns_t *)request, (svl_statistic_dns_t *)statistic, connection->buffer);
        else if (strncmp(url->scheme, "http", 4) == 0)
            svl_request_http_response((svl_request_http_t *)request, (svl_statistic_http_t *)statistic, connection->buffer);
        if (!(request->flags & SVL_FLAG_DONE))
            return;
        svl_statistic_response(statistic, request->response);
        svl_queue_pop(connection->read);
        if (request->flags & SVL_FLAG_CLOSE && svl_queue_peek(connection->read) != NULL) {
            while (svl_queue_pop(connection->read) != NULL) {
                statistic->pipeline++;
                statistic->error++;
            }
            svl_connection_close(connection);
            return;
        }
        if (request->flags & SVL_FLAG_CLOSE)
            svl_connection_close(connection);
    }
    connection->descriptor->events = 0;
}

static void
svl_connection_error(svl_connection_t *connection, svl_statistic_t *statistic, int error) {
    struct pollfd *descriptor = connection->descriptor;
    svl_request_t *request;

    if (error == EINTR) /* todo: || error == EAGAIN || error == EINPROGRESS) ? */
        return;
    if (error == ECONNRESET || error == EPIPE)
        statistic->econnreset++;
    else if (error == ETIMEDOUT)
        statistic->etimedout++;
    else if (error == ECONNREFUSED)
        statistic->econnrefused++;
    else {
        errno = error;
        svl_context->statistic->duration = svl_timestamp_now() - svl_context->statistic->duration;
        svl_context_statistic(svl_context);
        err(EX_OSERR, "connection error");
    }
    if (descriptor->events == (POLLOUT | POLLWRBAND) &&
        svl_queue_pop(connection->write) != NULL) {
        statistic->pipeline++;
        statistic->error++;
    }
    else if (descriptor->events == (POLLIN | POLLPRI)) {
        while ((request = svl_queue_pop(connection->read)) != NULL) {
            statistic->pipeline++;
            statistic->error++;
        }
    }
    svl_connection_close(connection);
}

static void
svl_connection_close(svl_connection_t *connection) {
    struct pollfd *descriptor = connection->descriptor;
    int result;

    if (connection->buffer != NULL) {
        connection->buffer->offset = connection->buffer->length; /* drop read buffer */
        svl_buffer_compact(connection->buffer);
    }
    if (connection->ssl != NULL) {
        if ((result = SSL_shutdown(connection->ssl)) == SVL_ERROR)
            errx(EX_SOFTWARE, "ssl_shutdown failed %s", ERR_error_string((unsigned int)SSL_get_error(connection->ssl, result), NULL));
        if (result == SVL_FALSE && SSL_shutdown(connection->ssl) == SVL_ERROR) /* bidirectional shutdown */
            errx(EX_SOFTWARE, "ssl_shutdown failed %s", ERR_error_string((unsigned int)SSL_get_error(connection->ssl, result), NULL));
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }
    if (descriptor->fd != SVL_UNDEFINED)
        close(descriptor->fd);
    descriptor->fd = SVL_UNDEFINED;
    descriptor->events = 0;
    descriptor->revents = 0;
}

static void
svl_connection_process(svl_connection_t *connection, svl_statistic_t *statistic, svl_url_t *url) {
    struct pollfd *descriptor = connection->descriptor;
    int error = 0;
    socklen_t size = sizeof(error);

    if (descriptor->revents & POLLNVAL)
        errx(EX_IOERR, "invalid descriptor");
    /* pollhup is handled in connection read */
    if (descriptor->revents & POLLERR) {
        if (getsockopt(descriptor->fd, SOL_SOCKET, SO_ERROR, &error, &size) == SVL_ERROR)
            err(EX_OSERR, "getsockopt failed");
        svl_connection_error(connection, statistic, error);
    }
    if (descriptor->revents & POLLOUT || descriptor->revents & POLLWRBAND)
        svl_connection_write(connection, statistic);
    if (descriptor->revents & POLLIN || descriptor->revents & POLLPRI)
        svl_connection_read(connection, statistic, url);
}

static void
svl_connection_timeout(svl_connection_t *connection, svl_statistic_t *statistic) {
    svl_request_t *request;
    unsigned long timeout = statistic->timeout;

    while ((request = svl_queue_peek(connection->write)) != NULL &&
            svl_request_timeout(request) == SVL_TRUE) {
        svl_queue_pop(connection->write);
        statistic->timeout++;
        statistic->error++;
    }
    if ((request = svl_queue_peek(connection->read)) != NULL &&
         svl_request_timeout(request) == SVL_TRUE) {
        while (svl_queue_pop(connection->read) != NULL) {
            statistic->timeout++;
            statistic->error++;
        }
    }
    if (statistic->timeout > timeout)
        svl_connection_close(connection);
}

static int
svl_connection_busy(svl_connection_t *connection) {
    if (svl_queue_peek(connection->write) == NULL && 
        svl_queue_peek(connection->read) == NULL)
        return SVL_FALSE;
    return SVL_TRUE;
}

static int
svl_connection_event(svl_connection_t *connection) {
    if (connection->descriptor->revents == 0)
        return SVL_FALSE;
    return SVL_TRUE;
}

static void
svl_connection_link(svl_connection_t *connection_a, svl_connection_t *connection_b) {
    if (connection_a != NULL)
        connection_a->next = connection_b;
    if (connection_b != NULL)
        connection_b->previous = connection_a;
}

static void
svl_connection_unlink(svl_connection_t *connection) {
    svl_connection_link(connection->previous, connection->next);
    connection->previous = NULL;
    connection->next = NULL;
}

static void
svl_connection_free(svl_connection_t *connection) {
    if (connection == NULL)
        return;
    svl_connection_close(connection);
    svl_buffer_free(connection->buffer);
    free(connection->write);
    free(connection->read);
    SSL_free(connection->ssl);
    /* descriptor and connection free is done in pool */
}

static void
svl_list_append(svl_list_t *list, svl_connection_t *connection) {
    svl_connection_link(list->tail, connection);
    if (list->head == NULL)
        list->head = connection;
    list->tail = connection;
    list->length++;
}

static svl_connection_t *
svl_list_head(svl_list_t *list) {
    return list->head;
}

static svl_connection_t *
svl_list_next(svl_list_t *list) {
    svl_connection_t *connection = list->next;

    list->next = (list->next == NULL) ? list->head : list->next->next;
    return connection;
}

static void
svl_list_remove(svl_list_t *list, svl_connection_t *connection) {
    if (list->head == connection)
        list->head = connection->next;
    if (list->tail == connection)
        list->tail = connection->previous;
    svl_connection_unlink(connection);
    list->length--;
}

static void 
svl_pool_setup(svl_pool_t *pool, size_t length) {
    struct rlimit limit = { 0, 0 };
    size_t i;

    if (getrlimit(RLIMIT_NOFILE, &limit) == SVL_ERROR)
        err(EX_OSERR, "getrlimit failed");
    limit.rlim_cur = limit.rlim_max; /* try increasing open descriptors limit */
    if (setrlimit(RLIMIT_NOFILE, &limit) == SVL_ERROR)
        err(EX_OSERR, "setrlimit failed");
    if (length + SVL_POOL_RESERVED > limit.rlim_cur)
        length = limit.rlim_cur - SVL_POOL_RESERVED; /* standard in out and error are reserved */
    pool->connections = svl_calloc(length, sizeof(svl_connection_t));
    pool->descriptors = svl_calloc(length, sizeof(struct pollfd));
    pool->length = length;
    pool->busy = svl_calloc(1, sizeof(svl_list_t));
    for (i = 0; i < pool->length; i++) {
        svl_connection_setup(&pool->connections[i], &pool->descriptors[i]);
        pool->descriptors[i].fd = SVL_UNDEFINED;
    }
}

static void
svl_pool_open(svl_pool_t *pool, svl_address_t *address, SSL_CTX *ssl_context) {
    svl_connection_t *connection;

    pool->busy->next = svl_list_head(pool->busy);
    while ((connection = svl_list_next(pool->busy)) != NULL)
        svl_connection_open(connection, address, ssl_context);
}

static void
svl_pool_poll(svl_pool_t *pool) {
    svl_timestamp_t timeout = SVL_POLL_TIMEOUT / SVL_PREFIX_MILLI;

    if (timeout > INT_MAX)
        errx(EX_SOFTWARE, "timeout overflow");
    pool->events = poll(pool->descriptors, pool->length, (int)timeout);
    if (pool->events == SVL_ERROR && errno != EINTR)
        err(EX_OSERR, "poll failed");
}

static void
svl_pool_process(svl_pool_t *pool, svl_statistic_t *statistic, svl_url_t *url) {
    svl_connection_t *connection;

    svl_pool_poll(pool);
    if (pool->events == 0) { /* poll timeout */
        pool->busy->next = svl_list_head(pool->busy);
        while ((connection = svl_list_next(pool->busy)) != NULL) {
            svl_connection_timeout(connection, statistic);
            if (svl_connection_busy(connection) == SVL_FALSE)
                svl_list_remove(pool->busy, connection);
        }
    }
    if (pool->events > 0) {
        pool->busy->next = svl_list_head(pool->busy);
        while ((connection = svl_list_next(pool->busy)) != NULL && pool->events > 0) {
            if (svl_connection_event(connection) == SVL_FALSE)
                continue;
            svl_connection_process(connection, statistic, url);
            if (svl_connection_busy(connection) == SVL_FALSE)
                svl_list_remove(pool->busy, connection);
            pool->events--;
        }
    }
}

static void
svl_pool_status(svl_pool_t *pool) {
    printf("%-32s %lu\n", "Connections busy:", pool->busy->length);
}

static void
svl_pool_free(svl_pool_t *pool) {
    size_t i;

    if (pool == NULL)
        return;
    free(pool->busy);
    for (i = 0; i < pool->length; i++)
        svl_connection_free(&pool->connections[i]);
    free(pool->descriptors);
    free(pool->connections);
    free(pool);
}

static void
svl_statistic_connect(svl_statistic_t *statistic, svl_timestamp_t timestamp) {
    if (statistic->connections == SIZE_T_MAX)
        errx(EX_SOFTWARE, "connections overflow");
    statistic->connects = svl_crealloc(statistic->connects, statistic->connections, statistic->connections + 1, sizeof(svl_timestamp_t));
    statistic->connects[statistic->connections++] = timestamp;
}

static void
svl_statistic_response(svl_statistic_t *statistic, svl_timestamp_t response) {
    if (statistic->done == SIZE_T_MAX)
        errx(EX_SOFTWARE, "done overflow");
    statistic->responses = svl_crealloc(statistic->responses, statistic->done, statistic->done + 1, sizeof(svl_timestamp_t));
    statistic->responses[statistic->done++] = response;
    if (response > SVL_REQUEST_SLA)
        statistic->sla++;
}

static void
svl_statistic_status(svl_statistic_t *statistic) {
    printf("%-32s %lu (done: %lu error: %lu)\n", "Total requests:",
           (unsigned long)statistic->requests, 
           (unsigned long)statistic->done, (unsigned long)statistic->error);
}

static void
svl_statistic_print(svl_statistic_t *statistic) {
    puts("[General]");
    printf("%-32s %lu\n", "Total connections:", statistic->connections);
    printf("%-32s %lu (done: %lu error: %lu)\n", "Total requests:",
           (unsigned long)statistic->requests, 
           (unsigned long)statistic->done, (unsigned long)statistic->error);
    printf("%-32s ", "Total transferred:");
    svl_statistic_bytes((double)statistic->bytes);
    printf("\n");
    printf("%-32s %f seconds\n", "Total duration:", statistic->duration);
    printf("%-32s ", "Transfer throughput:");
    svl_statistic_bytes(statistic->bytes / (double)statistic->duration);
    printf("/second\n");
    printf("%-32s %f requests/second\n", "Request throughput:", (statistic->done + statistic->error) / (double)statistic->duration);
    /* transfer time and size are not interesting */
    puts("[Network]");
    if (statistic->connections == 0)
        puts("No connect done successful!");
    else {
        printf("%-32s %f milliseconds\n", "Connect time median:",
                svl_timestamp_median(statistic->connects, statistic->connections) / SVL_PREFIX_MILLI);
        printf("%-32s %f milliseconds\n", "Connect time maximum:",
                statistic->connects[statistic->connections - 1] / SVL_PREFIX_MILLI);
        printf("%-32s %f milliseconds\n", "Connect time minimum:",
                statistic->connects[0] / SVL_PREFIX_MILLI);
    }
    printf("%-32s %lu\n", "Error connection reset:", statistic->econnreset);
    printf("%-32s %lu\n", "Error connection timeout:", statistic->etimedout);
    printf("%-32s %lu\n", "Error connection refused:", statistic->econnrefused);
    puts("[Requests]");
    if (statistic->done == 0)
        puts("No request done successful!");
    else {
        printf("%-32s %f milliseconds\n", "First response time median:",
               svl_timestamp_median(statistic->responses, statistic->done) / SVL_PREFIX_MILLI);
        printf("%-32s %f milliseconds\n", "First response time maximum:",
               statistic->responses[statistic->done - 1] / SVL_PREFIX_MILLI);
        printf("%-32s %f milliseconds\n", "First response time minimum:",
               statistic->responses[0] / SVL_PREFIX_MILLI);
        printf("%-32s %lu (SLA: %f percent)\n", "Missed SLA ("SVL_QUOTE(SVL_REQUEST_SLA)" seconds):", statistic->sla, 
               ((statistic->done + statistic->error - statistic->sla) / (double)(statistic->done + statistic->error)) * 100);
    }
    printf("%-32s %lu\n", "Error timeout ("SVL_QUOTE(SVL_REQUEST_TIMEOUT)" seconds):", statistic->timeout);
    printf("%-32s %lu\n", "Error disrupt pipeline:", statistic->pipeline);
}

static void
svl_statistic_bytes(double bytes) {
    if (bytes > SVL_PREFIX_GIGA)
        printf("%f gbytes", bytes / SVL_PREFIX_GIGA);
    else if (bytes > SVL_PREFIX_MEGA)
        printf("%f mbytes", bytes / SVL_PREFIX_MEGA);
    else if (bytes > SVL_PREFIX_KILO)
        printf("%f kbytes", bytes / SVL_PREFIX_KILO);
    else
        printf("%f bytes", bytes);
    fflush(stdout);
}

static void
svl_statistic_free(svl_statistic_t *statistic) {
    if (statistic == NULL)
        return;
    free(statistic->responses);
    free(statistic->connects);
    free(statistic);
}

static void
svl_statistic_dns_print(svl_statistic_dns_t *statistic) {
    puts("[DNS Service]");
    (void)statistic; /* silence compiler warning until implemented */
    /* todo */
}

static void
svl_statistic_http_print(svl_statistic_http_t *statistic) {
    puts("[HTTP Service]");
    printf("%-32s %lu (404 Not Found: %lu 5xx Server Error: %lu)\n", "Mismatch status:", statistic->mismatch, statistic->not_found, statistic->server_error);
}

static void
svl_context_setup(svl_context_t *context, const char *url, const char *file,
                  const char *method, const char *factor) {
    printf("Setup servload[%d]... "SVL_ANSI_SC, getpid());
    fflush(stdout);
    context->url = svl_calloc(1, sizeof(svl_url_t));
    svl_url_parse(context->url, url);
    context->address = svl_calloc(1, sizeof(svl_address_t));
    svl_address_resolve(context->address, context->url);
    if (strcmp(context->url->scheme, "https") == 0) {
        SSL_load_error_strings();
        SSL_library_init();
        context->ssl_context = SSL_CTX_new(SSLv23_client_method());
        if (context->ssl_context == NULL)
            errx(EX_SOFTWARE, "ssl_ctx_new failed %s", ERR_error_string(ERR_get_error(), NULL));
    }
    context->file = svl_calloc(1, sizeof(svl_file_t));
    svl_file_setup(context->file, file);
    context->method = svl_calloc(1, sizeof(svl_method_t));
    svl_method_parse(context->method, method, factor);
    context->sequence = svl_calloc(1, sizeof(svl_sequence_t));
    svl_sequence_setup(context->sequence);
    svl_sequence_load(context->sequence, context->url, context->file);
    svl_sequence_analyse(context->sequence);
    if (context->method->name != NULL)
        svl_sequence_modify(context->sequence, context->url, context->method);
    svl_sequence_prepare(context->sequence, context->url, context->method);
    context->pool = svl_calloc(1, sizeof(svl_pool_t));
    svl_pool_setup(context->pool, context->sequence->sessions->length);
    if (strcmp(context->url->scheme, "dns") == 0)
        context->statistic = svl_calloc(1, sizeof(svl_statistic_dns_t));
    else if (strncmp(context->url->scheme, "http", 4) == 0)
        context->statistic = svl_calloc(1, sizeof(svl_statistic_http_t));
    context->statistic->requests = context->sequence->length;
    printf(SVL_ANSI_RC);
    printf(SVL_ANSI_CE"Done.\n");
}

static void
svl_context_setting(svl_context_t *context) {
    svl_url_t *url = context->url;
    svl_file_t *file = context->file;
    svl_method_t *method = context->method;
    svl_sequence_t *sequence = context->sequence;
    int tty = isatty(fileno(stdout));

    if (tty == SVL_TRUE)
        svl_sequence_plot(context->sequence);
    printf("URL: %s://%s", url->scheme, url->host);
    (strlen(url->port) == 0) ? puts("/") : printf(":%s/\n", url->port);
    printf("File: %s Method: %s Factor: %hu\n", 
           file->path, (method->name == NULL) ? "none" : method->name, method->factor);
    printf("Requests: %lu Sessions: %lu Duration: %f seconds\n", 
           (unsigned long)sequence->length, (unsigned long)sequence->sessions->length, sequence->duration);    
    if (tty == SVL_TRUE)
        svl_continue();
    if (svl_terminate == SVL_FALSE) {
        printf("Running servload... ");
        fflush(stdout);
    }
}

static void
svl_context_timer(svl_context_t *context) {
    svl_request_t *request;
    struct itimerval timer;
    double fractional, integral;

    for (; context->timer < context->sequence->length; context->timer++) {
        request = context->sequence->requests[context->timer];
        if (request->wait == 0 || request->flags & SVL_FLAG_TIMER)
            continue;
        memset(&timer, 0, sizeof(struct itimerval));
        fractional = modf(request->wait, &integral);
        timer.it_value.tv_sec = (time_t)integral;
        timer.it_value.tv_usec = (long)(fractional / SVL_PREFIX_MICRO);
        if (setitimer(ITIMER_REAL, &timer, NULL) == SVL_ERROR)
            err(EX_OSERR, "setitimer failed");
        request->flags |= SVL_FLAG_TIMER; /* mark wait timer done */
        break;
    }
}

static void
svl_context_status(svl_context_t *context) {
    svl_pool_status(context->pool);
    svl_statistic_status(context->statistic);
}

static void
svl_context_process(svl_context_t *context) {
    svl_request_t *request;
    svl_session_t *session;
    svl_connection_t *connection;

    for (; context->queue < context->sequence->length; context->queue++) {
        if (context->queue == context->timer)
            break;
        request = context->sequence->requests[context->queue];
        session = svl_hash_lookup(context->sequence->sessions, request->key); /* this may be slow */
        connection = &context->pool->connections[session->id % context->pool->length]; /* explictly allow nested sessions for better replay */
        if (svl_connection_busy(connection) == SVL_FALSE) /* append connection exactly once */
            svl_list_append(context->pool->busy, connection);
        svl_queue_push(connection->write, request);
    }
    svl_pool_open(context->pool, context->address, context->ssl_context);
    svl_pool_process(context->pool, context->statistic, context->url);
    if (context->queue >= context->sequence->length && 
        svl_list_head(context->pool->busy) == NULL)        
        svl_terminate = SVL_TRUE;
}

static void
svl_context_statistic(svl_context_t *context) {
    svl_url_t *url = context->url;

    puts("Done.");
    svl_statistic_print(context->statistic);
    if (strcmp(url->scheme, "dns") == 0)
        svl_statistic_dns_print((svl_statistic_dns_t *)context->statistic);
    else if (strncmp(url->scheme, "http", 4) == 0)
        svl_statistic_http_print((svl_statistic_http_t *)context->statistic);
}

static void
svl_context_free(svl_context_t *context) {
    if (context == NULL)
        return;
    svl_statistic_free(context->statistic);
    svl_pool_free(context->pool);
    svl_sequence_free(context->sequence);
    free(context->method);
    svl_file_free(context->file);
    SSL_CTX_free(context->ssl_context);
    free(context->address);
    free(context->url);
    free(context);
}

static void
svl_exit(void) {
    svl_context_free(svl_context);
    svl_context = NULL;
}

static void
svl_signal(int number) {
    if (number == SIGALRM)
        svl_alarm = SVL_TRUE;
    else if (number == SIGINT || number == SIGTERM)
        svl_terminate = SVL_TRUE;
    else if (number == SIGINFO)
        svl_info = SVL_TRUE;
}

int
main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        printf("%s "SVL_VERSION" (c) "SVL_YEAR" Jörg Zinke\n", argv[0]);
        exit(EX_OK);
    }
    if (argc < 3 || argc > 5)
        errx(EX_USAGE, "Usage: %s url file [method] [factor]", argv[0]);
    if (atexit(&svl_exit) == SVL_ERROR)
        err(EX_OSERR, "atexit failed");
    signal(SIGALRM, svl_signal);
    signal(SIGINT, svl_signal);
    signal(SIGTERM, svl_signal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINFO, svl_signal);
    svl_context = svl_calloc(1, sizeof(svl_context_t));
    svl_context_setup(svl_context, argv[1], argv[2], (argc >= 4) ? argv[3] : NULL,
                                                     (argc == 5) ? argv[4] : NULL);
    svl_context_setting(svl_context);
    svl_context->statistic->duration = svl_timestamp_now();
    while (svl_terminate == SVL_FALSE) {
        if (svl_alarm == SVL_TRUE) {
            svl_alarm = SVL_FALSE;
            svl_context_timer(svl_context);
        }
        if (svl_info == SVL_TRUE) {
            svl_info = SVL_FALSE;
            svl_context_status(svl_context);
        }
        svl_context_process(svl_context);
    }
    svl_context->statistic->duration = svl_timestamp_now() - svl_context->statistic->duration;
    svl_context_statistic(svl_context);
    svl_context_free(svl_context);
    svl_context = NULL;
    return EX_OK;
}
