#include "tlsperf.h"
#include "server.h"
#include "connection.h"

using namespace node;
using namespace v8;
using namespace std;

namespace tlsperf {
    
    Persistent<Object> module_handle;
    
    int Server::init_dh(const char *cert)
    {
        DH *dh;
        BIO *bio;

        assert(cert);

        bio = BIO_new_file(cert, "r");
        if (!bio) {
          ERR_print_errors_fp(stderr);
          return -1;
        }

        dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!dh) {
            ERR("{server} Note: no DH parameters found in %s\n", cert);
            return -1;
        }

        LOG("{server} Using DH parameters from %s\n", cert);
        SSL_CTX_set_tmp_dh(m_ssl_ctx, dh);
        LOG("{server} DH initialized with %d bit key\n", 8*DH_size(dh));
        DH_free(dh);

        return 0;
    }

    void Server::setup_openssl()
    {
        SSL_library_init();
        SSL_load_error_strings();
        long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL |
                SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

        if (OPTIONS.ETYPE == ENC_TLS)
            m_ssl_ctx = SSL_CTX_new(TLSv1_server_method());
        else if (OPTIONS.ETYPE == ENC_SSL)
            m_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        else
            assert(OPTIONS.ETYPE == ENC_TLS || OPTIONS.ETYPE == ENC_SSL);

#ifdef SSL_OP_NO_COMPRESSION
        ssloptions |= SSL_OP_NO_COMPRESSION;
#endif

        SSL_CTX_set_options(m_ssl_ctx, ssloptions);
        SSL_CTX_set_info_callback(m_ssl_ctx, info_callback);

        if (SSL_CTX_use_certificate_chain_file(m_ssl_ctx, OPTIONS.CERT_FILE) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("{server} cannot load tlsperf cert file, no such file or cert.");
        }
        if (SSL_CTX_use_RSAPrivateKey_file(m_ssl_ctx, OPTIONS.CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("{server} cannot load tlsperf cert file, no private key.");
        }

#ifndef OPENSSL_NO_DH
        init_dh(OPTIONS.CERT_FILE);
#endif /* OPENSSL_NO_DH */
        if (OPTIONS.ENGINE) {
            ENGINE *e = NULL;
            ENGINE_load_builtin_engines();
            if (!strcmp(OPTIONS.ENGINE, "auto"))
                ENGINE_register_all_complete();
            else {
                if ((e = ENGINE_by_id(OPTIONS.ENGINE)) == NULL ||
                    !ENGINE_init(e) ||
                    !ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                    ERR_print_errors_fp(stderr);
                    throw std::runtime_error("Invalid openssl engine.");
                }
                LOG("{server} will use OpenSSL engine %s.\n", ENGINE_get_id(e));
                ENGINE_finish(e);
                ENGINE_free(e);
            }
        }

        if (OPTIONS.CIPHER_SUITE)
            if (SSL_CTX_set_cipher_list(m_ssl_ctx, OPTIONS.CIPHER_SUITE) != 1)
                ERR_print_errors_fp(stderr);
    }

    void Server::timer_cb(uv_timer_t* handle, int status) 
    {
        Server *instance = (Server *)handle->data;
        //LOG("Timer callback called. after %ld ms\n",
        //    (long int)(uv_now(uv_default_loop()) - instance->m_start_time));
        uint64_t free_mem = uv_get_free_memory();
        uint64_t total_mem = uv_get_total_memory();
        
        LOG("{stats} clients:%d, free_mem=%llu, total_mem=%llu\n", 
            _connection_cnt, (long long unsigned int)free_mem, (long long unsigned int)total_mem);


        instance->timer_again();
    }
    
    void Server::loop_poller_cb(uv_timer_t* handle, int status)
    {
        Server *instance = (Server *)handle->data;
        instance->runServerLoopHack();
        instance->poller_again();
    }
    
    void Server::io_idle_cb(ev::idle &w, int revents)
    {
        LOG("server socket idle called.\n");
    }

    void Server::setup_socket()
    {
        struct addrinfo *ai, hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
        const int gai_err = getaddrinfo(OPTIONS.FRONT_IP, OPTIONS.FRONT_PORT,
                                        &hints, &ai);
        if (gai_err != 0) {
            ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
            exit(1);
        }

        m_s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

        if (m_s == -1)
          fail("{socket: main}");

        int t = 1;
        setsockopt(m_s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
        set_socket_nonblocking(m_s);

        if (bind(m_s, ai->ai_addr, ai->ai_addrlen)) {
            fail("{bind-socket}");
        }

#if TCP_DEFER_ACCEPT
        int timeout = 1;
        setsockopt(m_s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
#endif /* TCP_DEFER_ACCEPT */


        freeaddrinfo(ai);
        listen(m_s, OPTIONS.BACKLOG);        
    }
    
    void Server::io_accept(ev::io &watcher, int revents) {
        LOG("{client} new connection.\n");
        
        if (EV_ERROR & revents) {
            perror("got invalid event");
            return;
        }
        struct sockaddr_in addr;
        socklen_t sl = sizeof(addr);
        
        int client_sd = accept(watcher.fd, (struct sockaddr *) &addr, &sl);
        if(client_sd == -1) {
            switch(errno) {
                case EMFILE:
                    ERR("{client} accept() failed; too many open files for this process\n");
                    break;

                case ENFILE:
                    ERR("{client} accept() failed; too many open files for this system\n");
                    break;

                case 'k':
                    OPTIONS.TCP_KEEPALIVE = atoi(optarg);
                    break;

                default:
                    assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
                    break;
            }
            return;
        }
        int flag = 1;
        int ret = setsockopt(client_sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
        if (ret == -1) {
          perror("{client} Couldn't setsockopt on client (TCP_NODELAY)\n");
        }
    #ifdef TCP_CWND
        int cwnd = 10;
        ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
        if (ret == -1) {
          perror("{client} Couldn't setsockopt on client (TCP_CWND)\n");
        }
    #endif

        set_socket_nonblocking(client_sd);
        set_socket_tcpkeepalive(client_sd);
        
        char address_buffer[16] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, address_buffer, sizeof(address_buffer));
        
        LOG("accepted SSL/TLS connection from %s on fd:%d\n", address_buffer, client_sd);
        
        Connection *client = new Connection(client_sd, (struct sockaddr *)&addr, m_loop, m_ssl_ctx);
        assert(client);

//Segfault on callback with new connection wraped object.. I am missing somthing here.
//        Local<Value> argv[1];
//        Local<Object> conn;
//        client->Wrap(conn);
//        argv[0] = conn;
//        
//        m_connection_callback->Call(Context::GetCurrent()->Global(), 1, argv);
        
    }
    
    void Server::start_listen(int port)
    {
        
        //Create main server socket on port
        setup_socket();
        //Setup openssl context, load certs...etc
        setup_openssl();
        
        m_io.set<Server, &Server::io_accept>(this);
        m_idle.set<Server, &Server::io_idle_cb>(this);
        m_io.start(m_s, ev::READ);
        
        //DEBUG break on sigint aka ctrl-c
        m_sio.set<&Server::signal_cb>();
        m_sio.start(SIGINT);

        LOG("{server} starting server loop.\n");
        
//        m_loop.run(0); //Never returns as libev is designed, must be in a thread test with
//      using the libuv wrapper/timer as  a polling for the SERVER loop this just may not work!
        m_loop.run(ev::NOWAIT);

        uv_timer_init(uv_default_loop(), &m_polling_handle);
        m_polling_handle.data = this;
        uv_timer_start(&m_polling_handle, &Server::loop_poller_cb, 1, 1);
        
        m_start_time = uv_now(uv_default_loop());
        uv_timer_init(uv_default_loop(), &m_timer_handle);
        //Use timer_handle data as ref to this
        m_timer_handle.data = this;
        //Start watcher timer for stats and server state monitoring, 
        //  start 5s and repeat every 5s
        uv_timer_start(&m_timer_handle, &Server::timer_cb, 5000, 5000);

        LOG("{server} Listening on port %d.\n", port);
    }
    
    /////
    //Node/v8 API interface
    /////
    void Server::Initialize(Handle<Object> target){
        HandleScope scope;

        Local<FunctionTemplate> t = FunctionTemplate::New(New);

        s_ct = Persistent<FunctionTemplate>::New(t);
        s_ct->InstanceTemplate()->SetInternalFieldCount(1);
        s_ct->SetClassName(String::NewSymbol("Server"));

        NODE_SET_PROTOTYPE_METHOD(s_ct, "listen", Listen);

        target->Set(String::NewSymbol("Server"),
        s_ct->GetFunction());
        
        
        _connection_counter = 0; //starts at zero and never resets for life of process
        _connection_cnt = 0; //will be incremented and decremented to track current number of clients

        module_handle = Persistent<Object>::New(target);
    }
    
    Handle<Value> Server::New(const Arguments& args)
    {
        HandleScope scope;
        assert(args.IsConstructCall());
        if (!args[0]->IsObject())
            return ThrowException(Exception::TypeError(
              String::New("Argument should be an integer")));
        Local<Object> options = args[0]->ToObject();
        
        String::Utf8Value key(options->Get(String::New("key"))->ToString());
        
        cout << "Javascript options object value for cert key:" << *key << endl;

        if (args.Length() > 1 && !args[1]->IsFunction())
          return ThrowException(Exception::TypeError(
            String::New("Provided callback must be a function")));
        Local<Function> cb = Local<Function>::Cast(args[1]);
        
        Server* instance = new Server(Persistent<Function>::New(cb));

        instance->Wrap(args.This());
        return scope.Close(args.This());
    }

} /* namespace tlsperf */
