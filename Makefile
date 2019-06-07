all:
	make -C server
	make -C client

clean:
	make -C server clean
	make -C client clean
	rm -f server_main client_main

certs:
	openssl genrsa -des3 -passout pass:ABCD -out server.pass.key 2048
	openssl rsa -passin pass:ABCD -in server.pass.key -out server.key
	rm -f server.pass.key
	openssl req -new -key server.key -out server.csr
	openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
	rm -f server.csr
	openssl genrsa -des3 -passout pass:ABCD -out client.pass.key 2048
	openssl rsa -passin pass:ABCD -in client.pass.key -out client.key
	rm -f client.pass.key
	openssl req -new -key client.key -out client.csr
	openssl x509 -req -sha256 -days 365 -in client.csr -signkey client.key -out client.crt
	rm -f client.csr
	cp server.crt server.key server
	cp client.crt client.key client
