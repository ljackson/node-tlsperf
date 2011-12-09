/* 
 * File:   connection.cc
 * Author: leif
 *
 * Created on December 7, 2011, 4:15 PM
 */

#include "tlsperf.h"
#include "connection.h"

using namespace std;
using namespace node;
using namespace v8;

namespace tlsperf {
    
    map<unsigned long, Connection *> _connection_map;
    
    void Connection::callback(ev::io &w, int revents)
    {
        if (EV_ERROR & revents) {
            perror("got invalid event");
            return;
        }
 
        if (revents & EV_READ)
            read_cb(w);
 
        if (revents & EV_WRITE)
            write_cb(w);
 
        m_io.set(ev::READ);
//        if (write_queue.empty()) {
//            io.set(ev::READ);
//        } else {
//            io.set(ev::READ|ev::WRITE);
//        }       
    }
    
    void Connection::write_cb(ev::io &w)
    {
        
    }
    
    void Connection::read_cb(ev::io &w)
    {
        char buffer[4096] = {0};
        int ssl_error = 0;
        size_t bytes = SSL_read(m_ssl, buffer, sizeof(buffer));
        if(bytes < 0) {
            ssl_error = SSL_get_error(m_ssl, bytes);
            switch(ssl_error) {
                case SSL_ERROR_WANT_READ:
                    return; //Ignore ssl doing it's thing
                case SSL_ERROR_SSL:
                    {
                        char errbuf[128] = {0};  // "errbuf must be at least 120 bytes long" -- ERR_error_string(3SSL)
                        ERR_error_string(ssl_error, errbuf);
                        stringstream ss;
                        ss << "{conn} " << m_id << " fd:" << m_sock_fd << " SSL_read  errors: " << errbuf;
                        while((ssl_error = ERR_get_error()) != 0) {
                            ERR_error_string(ssl_error, errbuf);
                            ss << ", ";
                            ss << errbuf;
                        }
                        ss << endl;
                        ERR(ss.str().c_str());
                        break;
                    }
                default:
                    ERR("{conn} %lu fd:%d other ssl error on SSL_read: %d\n",m_id, m_sock_fd, ssl_error);
                    break;
            }
            ERR("{conn} %lu fd:%d dropping connection due to ssl read error.\n", m_id, m_sock_fd);
            EmitError("ssl read error");
            EmitClose();
            Unref();
            //delete this; //not really "this" as it has been thunked into this method by ev++
            return;
        }
        
        if(bytes == 0) {
            LOG("{conn} %lu fd:%d disconnected\n", m_id, m_sock_fd);
            EmitClose();
            Unref(); //Let it get GC'ed by v8
//            delete this; //?? still feels icky
            return;
        }
        
        //LOG("{conn} %lu fd:%d Read data:'%s' from client.\n", m_id, m_sock_fd, buffer);
        EmitData(buffer,bytes);
    }
    
    void Connection::EmitData(const char *data, size_t bytes)
    {
        HandleScope scope;
        Local<Value> emit_v = m_instance->Get(String::NewSymbol("emit"));
        assert(emit_v->IsFunction());
        Local<Function> emit_f = emit_v.As<Function>();
        Handle<Value> argv[2] = {
            String::New("data"),
            Buffer::New(String::New(data, bytes))
        };
        TryCatch tc;
        emit_f->Call(m_instance, 2, argv);
        if(tc.HasCaught()) {
            ERR("{conn} %lu fd:%d exception on data event.", m_id, m_sock_fd);
            DisplayExceptionLine(tc);
        }        
    }
    
    void Connection::EmitClose()
    {
        HandleScope scope;
        Local<Value> emit_v = m_instance->Get(String::NewSymbol("emit"));
        assert(emit_v->IsFunction());
        Local<Function> emit_f = emit_v.As<Function>();
        Handle<Value> argv[1] = {
            String::New("close")
        };
        TryCatch tc;
        emit_f->Call(m_instance, 1, argv);
        if(tc.HasCaught()) {
            ERR("{conn} %lu fd:%d exception on close event.", m_id, m_sock_fd);
            DisplayExceptionLine(tc);
        }                
    }
    
    void Connection::EmitError(const char *error)
    {
        HandleScope scope;
        Local<Value> emit_v = m_instance->Get(String::NewSymbol("emit"));
        assert(emit_v->IsFunction());
        Local<Function> emit_f = emit_v.As<Function>();
        Handle<Value> argv[2] = {
            String::New("error"),
            Buffer::New(String::New(error))
        };
        TryCatch tc;
        emit_f->Call(m_instance, 2, argv);
        if(tc.HasCaught()) {
            ERR("{conn} %lu fd:%d exception on error event.", m_id, m_sock_fd);
            DisplayExceptionLine(tc);
        }                
    }
    
    
    void Connection::handshake_completed()
    {
        //OK ssl handshake completed, stop handshake io and switch to read/write cb's
        m_sslhandshake_io.stop();
        m_waiting_handshake = false;
        
        /* Disable renegotiation (CVE-2009-3555) */
        if(m_ssl->s3) {
            m_ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
        
        m_handshaked = true;

        //Call javascript callback to send wraped object as connected.
        this->getObjectInstance();
        Local<Value> argv[2] = {
            m_instance,
            Number::New(m_id)
        };
        m_connection_callback->Call(Context::GetCurrent()->Global(), 2, argv);
        
        m_io.set<Connection, &Connection::callback>(this);
        m_io.start(m_sock_fd, ev::READ | ev::WRITE);        
    }
    
    void Connection::sslhandshake_cb(ev::io &w, int revents)
    {
        int errcode;
        int error = SSL_do_handshake(m_ssl);
        if(error == 1) 
        {
            handshake_completed();
        }
        else
        {
            errcode = SSL_get_error(m_ssl, error);
            if(errcode == SSL_ERROR_WANT_READ || errcode == SSL_ERROR_WANT_WRITE) {
                return; //Nothing to do yet come back when SSL has enough data..etc.
            }
            else if (errcode == SSL_ERROR_ZERO_RETURN) 
            {
                LOG("{conn} %lu fd:%d Connection closed in ssl handshake\n", m_id, m_sock_fd);
            }
            else
            {
                LOG("{conn} %lu fd:%d Connection closed/invalid deleting connection.\n", m_id, m_sock_fd);
                delete this; //not really "this" as it has been thunked into this method by ev++
            }
        }
        
    }
    
    Connection::Connection(int s, sockaddr* addr, ev::dynamic_loop &loop, SSL_CTX * ctx):
        m_io(loop), m_sslhandshake_io(loop), 
        m_ssl(SSL_new(ctx)), m_sock_fd(s), 
        m_waiting_handshake(false),
        m_handshaked(false),
        m_renegotiation(false)
    {
        m_id = _connection_counter++;
        _connection_cnt++;
        
        LOG("{conn} %lu fd:%d got connection\n", m_id, m_sock_fd);
        
        _connection_map[m_id] = this; //Track connection object
        
        long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
        mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
        SSL_set_mode(m_ssl, mode);
        SSL_set_accept_state(m_ssl);
        SSL_set_fd(m_ssl, m_sock_fd);
        SSL_set_app_data(m_ssl, this); //Link this connection object to the SSL state
        
        LOG("{conn} %lu fd:%d ssl setup now waiting for handshake.\n", m_id, m_sock_fd);
        
        m_sslhandshake_io.set<Connection, &Connection::sslhandshake_cb>(this);
        m_sslhandshake_io.start(m_sock_fd, ev::READ | ev::WRITE); //Write nessary? 
        m_waiting_handshake = true; //Now marked as waiting for handshake_cb to complete before callback works...
    }
    
    Connection::~Connection(void) 
    {
        LOG("{conn} %lu fd:%d deleted.\n", m_id, m_sock_fd);
        Close();
    }
    
    void Connection::setConnectedCallback(Persistent<Function> cb)
    {
        m_connection_callback = cb;
    }
    
    /////
    //Node/v8 API interface
    /////
    void Connection::Initialize(Handle<Object> target)
    {
        HandleScope scope;
//        Local<FunctionTemplate> t = FunctionTemplate::New(New);
        Local<FunctionTemplate> t = FunctionTemplate::New();
        
        s_ct = Persistent<FunctionTemplate>::New(t);
        s_ct->InstanceTemplate()->SetInternalFieldCount(1);
        s_ct->SetClassName(String::NewSymbol("Connection"));
        
        NODE_SET_PROTOTYPE_METHOD(s_ct, "close", Close);

        target->Set(String::NewSymbol("Connection"), s_ct->GetFunction());        
    }

//We don't create Connection objects from Javascript, breaks wraping c++ created object    
//    Handle<Value> Connection::New(const Arguments& args)
//    {
//        HandleScope scope;
//        Handle<Object> external;
//        assert(args.IsConstructCall());
//        if(args[0]->IsExternal()) {
//            //Existing Connection object we are wrapping/aka copy constructor
//            external = Handle<Object>::Cast(args[0]);
//        }else{
//            return ThrowException(Exception::Error(
//                    String::New("cannot create a connection object directly!")));
//        }
//        
//        args.This()->SetInternalField(0, external);
//        
//        return scope.Close(args.This());
//    }
    
    Local<Object> Connection::getObjectInstance()
    {        
        HandleScope scope;
        if(m_instance.IsEmpty()) {
            Handle<ObjectTemplate> _instance_template = Connection::s_ct->InstanceTemplate();
            _instance_template->SetInternalFieldCount(1);
            Local<Object> conn_instance = _instance_template->NewInstance();

            m_instance = scope.Close(conn_instance);
            
            Wrap(m_instance);
            Ref();
        }
        
        return m_instance;
    }
    
    void Connection::Close()
    {
        if(m_waiting_handshake) 
        {
            m_sslhandshake_io.stop();
        }
        else
        {
            m_io.stop();
        }
        
        SSL_set_shutdown(m_ssl, SSL_SENT_SHUTDOWN);
        SSL_free(m_ssl);
        
        close(m_sock_fd);
        
        LOG("{conn} %lu fd:%d disconnected\n", m_id, m_sock_fd);
        
        _connection_map.erase(m_id); //Remove our object from tracking map where deleted duh!
        _connection_cnt--;        
    }
    
    Handle<Value> Connection::Close(const Arguments& args)
    {
        HandleScope scope;
        ObjectWrap::Unwrap<Connection>(args.This())->Close();
        return Undefined();
    }
    
} /* namespace tlsperf */
