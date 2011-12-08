var tls = require("./tlsperf")
    ,fs = require('fs')
    ,sys = require('util')
    ,port = 8443;

var options = {
    key: fs.readFileSync('certs/server-key.pem'),
    cert: fs.readFileSync('certs/server-cert.pem'),

    //client cert auth
    //requestCert: true,

    //Self signed cert for authoriziation
    //ca: [ fs.readFileSync('certs/client-cert.pem') ]
};

// Don't crash on errors
/*process.on('uncaughtException', function (err) {
    console.log("uncaughtException: %s", err);
    console.log(err.arguments[1].constructor.toString());
    console.log(err.stack);
});
*/
console.log("TLS server started.");

var server = tls.createServer(options, function (conn) {
    console.log("CALLBACK TLS connection established");
    //Inital version doesn't support streams
/*
    cleartextStream.addListener("data", function (data) {
         console.log("Data %d received", data.length);
    });

   cleartextStream.pipe(cleartextStream);
*/
    conn.on("data", function(buf) {
    });
    conn.on("close", function() {
    });
    conn.on("error", function(err) { 
    });
});

server.listen(port, function(data){
    console.log("TLS server listening.");
    //Running callback, FIXME: make this optional in C++ code
});

