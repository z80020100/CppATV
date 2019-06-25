#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>

#define HTTP_PROTOCOL_VERSION           "HTTP/1.1"
#define HTTP_REQUEST_METHOD_POST        "POST"

using namespace std;

class SimpleHttpClient {
public:
	SimpleHttpClient(char *host, int port);
	int tcpConnect();
	int tcpDisconnect();
	int sendData(const char *buf, int len);
	int recvData(char *buf, int len);

private:
	struct hostent *host_info;
	struct sockaddr_in server_addr; 
	int socket_fd;
};

