#include "tlsperf.h"
#include "server.h"
#include "connection.h"

using namespace node;
using namespace v8;
using namespace std;

namespace tlsperf {
    
    Persistent<FunctionTemplate> Server::s_ct;
    
    struct listen_baton_t {
        Server *instance;
        Persistent<Function> cb;
        int port;
    };

    Handle<Value> Server::Listen(const Arguments& args)
    {
        HandleScope scope;

        if (!args[0]->IsNumber())
            return ThrowException(Exception::TypeError(
              String::New("Argument should be an integer")));
        int port = args[0]->ToInteger()->Value();

        if (args.Length() > 1 && !args[1]->IsFunction())
          return ThrowException(Exception::TypeError(
            String::New("Provided callback must be a function")));
        Local<Function> cb = Local<Function>::Cast(args[1]);

        Server* instance = ObjectWrap::Unwrap<Server>(args.This());

        listen_baton_t *baton = new listen_baton_t();
        baton->instance = instance;
        baton->port = port;
        baton->cb = Persistent<Function>::New(cb);

        instance->Ref();

        eio_custom(EIO_Listen, EIO_PRI_DEFAULT, EIO_AfterListen, baton);
        ev_ref(EV_DEFAULT_UC);

        return Undefined();
    }

    void Server::EIO_Listen(eio_req *req)
    {
        listen_baton_t *baton = static_cast<listen_baton_t *>(req->data);
        baton->instance->start_listen(baton->port);
    }

    int Server::EIO_AfterListen(eio_req *req)
    {
        HandleScope scope;
        listen_baton_t *baton = static_cast<listen_baton_t *>(req->data);
        ev_unref(EV_DEFAULT_UC);
        baton->instance->Unref();

        Local<Value> argv[1];

        argv[0] = String::New("Hello World");

        TryCatch try_catch;

        baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);

        if (try_catch.HasCaught()) {
          FatalException(try_catch);
        }

        baton->cb.Dispose();

        delete baton;
        return 0;
    }

    static void Initialize(Handle<Object> target)
    {
        Server::Initialize(target);
        Connection::Initialize(target);
    }
} /* namespace tlsperf */

extern "C" {
  static void init (Handle<Object> target)
  {
    tlsperf::Initialize(target);
  }

  NODE_MODULE(tlsperf, init);
}

