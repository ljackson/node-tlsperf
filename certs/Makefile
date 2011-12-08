all: server_cert

server_cert:
	openssl req -x509 -nodes -days 1039 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem
	cat server-cert.pem server-key.pem > server.pem
