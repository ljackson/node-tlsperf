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
    
    void callback(ev::io &, int);
    void write_cb(ev::io &);
    void read_cb(ev::io &);
    void sslhandshake_cb(ev::io &, int);
    void handshake_completed();
    
    static Handle<Value> New(const Arguments& args);
    void Close();
    static Handle<Value> Close(const Arguments& args);
    
    
public:
    Connection(int s, struct sockaddr *addr, ev::dynamic_loop &loop, SSL_CTX * ctx);
    ~Connection(void);
    
    static void Initialize(Handle<Object> target);

    const bool isHandshaked() const { return m_handshaked; }
    void setRenegotiation(bool status) { m_renegotiation = status; }
};

extern std::map<unsigned long, Connection *> _connection_map;

} /* namespace tlsperf */
#endif	/* CONNECTION_H */

