var tls = require('tls')
    ,fs = require('fs')
    ,crypto = require('crypto')
    ,port = 8443 
    ,randomSize = 256
    ,numclients = 200
    ,requireAuth = false
    ,server = '127.0.0.1';

var opts = require('optimist')
            .usage("Usage: $0 [options]\nOptions:\n --port\n --rnd\n --clients\n --server\n");
var args = opts.argv;

// Don't crash on errors
process.on('uncaughtException', function (err) {
    console.log("uncaughtException: %s", err);
    console.log(err.arguments[1].constructor.toString());
    console.log(err.stack);
});

if(args.help) { 
    console.log(opts.help());
    process.exit();
}

if(args.port) {
    port = parseInt(args.port)
}
if(args.rnd) {
    randomSize = parseInt(args.rnd);
}

if(args.clients) {
    numclients = parseInt(args.clients);
}

if(args.server) {
    server = args.server;
}

if(args.auth) {
    requireAuth = true
}

console.log("With %d random data, connecting to %s on %d with %d clients", randomSize, server, port, numclients);

var buf;
if(randomSize == -1 ) {
    buf = new Buffer("test string");
}else{
    console.log("generated random data buffer\n");
    var data = crypto.randomBytes(randomSize);
    //console.log('Have %d bytes of random data: %s', data.length, data);
    console.log('Have %d bytes of random data', data.length);
    buf = new Buffer(data);

    console.log(buf.length + " bytes: " + buf.toString('utf8', 0, buf.length));
}

//process.exit();

var options = {
  // These are necessary only if using the client certificate authentication
  key: fs.readFileSync('certs/client-key.pem'),
  cert: fs.readFileSync('certs/client-cert.pem'),

  // This is necessary only if the server uses the self-signed certificate
  //ca: [ fs.readFileSync('certs/server-cert.pem') ]
};

if(requireAuth) {
    options['ca'] = [ fs.readFileSync('certs/server-cert.pem') ];
}

function connect(id) {
    console.log(id +" connecting\n");
    var client = null;
    client = tls.connect(port, server, options, function() {
        if (requireAuth == false || client.authorized) {
            console.log("%d Auth success, connected to TLS server\n", id);
            setInterval(function() {
                client.write(buf.toString('utf8',0,buf.length));
            }, 5000);
        }else{
            console.log("%d Failed to auth TLS connection: ", id);
            console.log(client.authorizationError);
        }
   });
};

//var i;
//for (i = 0; i< numclients; i++) {
//  connect(i);
//}
//FIXME change scale up algo, but seems nodetls client can only hit around 7.8k or so
var i = 0;
var cid = setInterval(function() {
    connect(++i);
    if(i >= numclients) { clearInterval(cid); }
}, 100);

