//Copyright Leif Jackson and other contributors. All rights reserved.
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to
//deal in the Software without restriction, including without limitation the
//rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//sell copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//IN THE SOFTWARE.

#ifndef TLSPERF_H
#define	TLSPERF_H

#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "node_defs.h"
#include <unistd.h>
#include "ev++.h"
#include <map>
#include <iostream>
#include <sstream>

#include <inttypes.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>

#include <sched.h>
#include <signal.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "util.h"

namespace tlsperf {
using v8::Object;
using v8::Handle;
using v8::Local;
using v8::Persistent;
using v8::Value;
using v8::HandleScope;
using v8::FunctionTemplate;
using v8::ObjectTemplate;
using v8::String;
using v8::Function;
using v8::TryCatch;
using v8::Context;
using v8::Arguments;
using v8::Integer;
using v8::Undefined;

#define LOG(...)                                        \
    do {                                                \
      if (!OPTIONS.QUIET) fprintf(stdout, __VA_ARGS__); \
      if (OPTIONS.SYSLOG) syslog(LOG_INFO, __VA_ARGS__);                    \
    } while(0)

#define ERR(...)                    \
    do {                            \
      fprintf(stderr, __VA_ARGS__); \
      if (OPTIONS.SYSLOG) syslog(LOG_ERR, __VA_ARGS__); \
    } while(0)

typedef enum {
    ENC_TLS,
    ENC_SSL
} ENC_TYPE;

typedef struct _options {
    ENC_TYPE ETYPE;
    const char *FRONT_IP;
    const char *FRONT_PORT;
    const char *CERT_FILE;
    const char *CIPHER_SUITE;
    const char *ENGINE;
    int BACKLOG;
    int QUIET;
    int SYSLOG;
    int TCP_KEEPALIVE;
} _options_t;

static _options_t OPTIONS = {
    ENC_SSL,      // ETYPE
    NULL,         // FRONT_IP
    "8443",       // FRONT_PORT
    "certs/server.pem",         // CERT_FILE
    "AES128-SHA:RC4:AES:CAMELLIA128-SHA:!ADH:!aNULL:!DH:!EDH:!eNULL:!LOW:!SSLv2:!EXP:!NULL",         // CIPHER_SUITE
    NULL,         // ENGINE
    3000,          // BACKLOG
    0,            // QUIET
    0,            // SYSLOG
    3600          // TCP_KEEPALIVE
};

void info_callback(const SSL *ssl, int where, int ret);
extern Persistent<Object> module_handle;

} /* namespace tlsperf */

#endif /* TLSPERF_H */