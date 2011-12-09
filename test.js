var tls = require("./tlsperf")
    ,fs = require('fs')
    ,sys = require('util')
    ,poll_interval = 10000
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

var cnt = 0;
var msg_cnt = 0, total_msg_cnt = 0;

var server = tls.createServer(options, function (conn, connection_id) {
    cnt++;
    console.log("%d CALLBACK TLS connection established", connection_id);
    //Inital version doesn't support streams
/*
    cleartextStream.addListener("data", function (data) {
         console.log("Data %d received", data.length);
    });

   cleartextStream.pipe(cleartextStream);
*/
    conn.on("data", function(buf) {
        msg_cnt++;
        total_msg_cnt++;
        //console.log("%d Got Data:'" + buf.toString() + "'", connection_id);
    });
    conn.on("close", function() {
        cnt--;
        console.log("%d Got Close.", connection_id);
        conn.close();
    });
    conn.on("error", function(err) { 
        console.log("%d Got Error:'" + buf.toString() + "'", connection_id);
    });
});

server.listen(port, function(data){
    console.log("TLS server listening.");
    //Running callback, FIXME: make this optional in C++ code
    mainLoopId = setInterval(function() {
        console.log("current connections: %d, tot msg %d at %d messages/s", cnt, total_msg_cnt, msg_cnt/(poll_interval / 1000));
        msg_cnt = 0;
    }, poll_interval);

});

