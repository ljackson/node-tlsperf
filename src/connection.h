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
 * File:   connection.h
 * Author: leif
 *
 * Created on December 7, 2011, 4:15 PM
 */

#ifndef CONNECTION_H
#define	CONNECTION_H
#include "tlsperf.h"

namespace tlsperf {
    
class Connection: node::ObjectWrap
{
    
friend class Server;
private:
    ev::io  m_io;
    ev::io  m_sslhandshake_io;
    SSL *   m_ssl;
    int     m_sock_fd;
    unsigned long m_id;
    bool    m_waiting_handshake;
    bool    m_handshaked;
    bool    m_renegotiation;
    
    Persistent<Function> m_connection_callback; //Callback from server
    Local<Object> m_instance; //Instance of Javascript object matching this ObjectWrap
    
    void callback(ev::io &, int);
    void write_cb(ev::io &);
    void read_cb(ev::io &);
    void sslhandshake_cb(ev::io &, int);
    void handshake_completed();
    
    //static Handle<Value> New(const Arguments& args);
    void Close();
    static Handle<Value> Close(const Arguments& args);
    
protected:
    Local<Object> getObjectInstance();
    void setConnectedCallback(v8::Persistent<v8::Function> m_connection_callback);
    void EmitData(const char *, size_t);
    void EmitClose();
    void EmitError(const char *);
public:
    static Persistent<FunctionTemplate> s_ct;
    
    Connection(int s, struct sockaddr *addr, ev::dynamic_loop &loop, SSL_CTX * ctx);
    ~Connection(void);
    
    static void Initialize(Handle<Object> target);

    const bool isHandshaked() const { return m_handshaked; }
    void setRenegotiation(bool status) { m_renegotiation = status; }
};

extern std::map<unsigned long, Connection *> _connection_map;

} /* namespace tlsperf */
#endif	/* CONNECTION_H */

