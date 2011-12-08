#include "tlsperf.h"
#include "connection.h"

namespace tlsperf {
    
    unsigned long _connection_counter;
    int _connection_cnt;
    
    /* This callback function is executed while OpenSSL processes the SSL
     *   handshake and does SSL record layer stuff.  It's used to trap
     *   client-initiated renegotiations.
     **/
    void info_callback(const SSL *ssl, int where, int ret) {
        (void)ret;
        if (where & SSL_CB_HANDSHAKE_START) {
            Connection *c = (Connection *)SSL_get_app_data(ssl);
            if (c->isHandshaked()) {
                c->setRenegotiation(true);
                LOG("{core} SSL renegotiation asked by client\n");
            }
        }
    }  
}
