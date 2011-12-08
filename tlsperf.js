var tlsperf = require(__dirname + '/build/Release/tlsperf.node')
    , events = require('events');

inherits(tlsperf.Server, events.EventEmitter);
inherits(tlsperf.Connection, events.EventEmitter);
exports.Server = tlsperf.Server;
exports.Connection = tlsperf.Connection;
exports.createServer = function(options, listener) {
  return new tlsperf.Server(options, listener);
};

// extend prototype
function inherits(target, source) {
  for (var k in source.prototype)
    target.prototype[k] = source.prototype[k];
}

