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
