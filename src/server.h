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

/* 
 * File:   server.h
 * Author: leif
 *
 * Created on December 7, 2011, 4:17 PM
 */

#ifndef SERVER_H
#define	SERVER_H
#include "tlsperf.h"
namespace tlsperf {

class Connection;
class Server: node::ObjectWrap
{
private: 
    SSL_CTX *   m_ssl_ctx;
    ev::dynamic_loop m_loop;
    ev::io      m_io;
    ev::sig     m_sio;
    ev::idle    m_idle;
    int m_s;
    uv_timer_t  m_timer_handle;
    uv_timer_t  m_polling_handle;
    
    v8::Persistent<v8::Function> m_connection_callback;

    int init_dh(const char *);
    void setup_openssl();
    void setup_socket();
    void set_socket_nonblocking(int fd) {
        int f = 1;
        assert (ioctl(fd, FIONBIO, &f) == 0);
    }
    void set_socket_tcpkeepalive(int fd) {
        int optval = 1;
        socklen_t optlen = sizeof(optval);

        if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
            ERR("Error activating SO_KEEPALIVE on client socket: %s", strerror(errno));
        }

        optval = OPTIONS.TCP_KEEPALIVE;
        optlen = sizeof(optval);
        if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
            ERR("Error setting TCP_KEEPIDLE on client socket: %s", strerror(errno));
        }        
    }
    
    static void fail(const char* s) {
        perror(s);
        exit(1);
    }

    struct ListenState;
    static Handle<Value> Listen(const Arguments &);
    static void EIO_Listen(eio_req *);
    static int EIO_AfterListen(eio_req *);

    void io_accept(ev::io &, int);
    void io_idle_cb(ev::idle &, int);
    
    static void signal_cb(ev::sig &signal, int revents) {
        signal.loop.break_loop();
    }
    
    static Handle<Value> New(const Arguments& args);
    Server(v8::Persistent<v8::Function> cb):
        m_io(m_loop), m_sio(m_loop),
        m_idle(m_loop), 
        m_s(-1), m_connection_callback(cb)
    {
    }
    
public:
    int64_t m_start_time;
    static Persistent<FunctionTemplate> s_ct;
    static void Initialize(Handle<Object> target);

    ~Server()
    {
    }

    static void timer_cb(uv_timer_t* , int);
    static void loop_poller_cb(uv_timer_t* , int);
    void start_listen(int);
    void poller_again() { uv_timer_again(&m_polling_handle); }
    void timer_again() {
        m_start_time = uv_now(uv_default_loop()); 
        uv_timer_again(&m_timer_handle);
    }
    void runServerLoopHack() {
        if(m_loop.raw_loop != NULL) {
            m_loop.run(ev::NOWAIT);
        }
    }
};

} /* namespace tlsperf */

#endif	/* SERVER_H */

