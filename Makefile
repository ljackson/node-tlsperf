all: tlsperf

tlsperf:
	node-waf build

clean:
	node-waf clean
