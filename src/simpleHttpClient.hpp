#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>

using namespace std;

class SimpleHttpClient {
public:
	SimpleHttpClient(char *host, int port);
	int tcpConnect();
	int tcpDisconnect();

private:
	struct hostent *host_info;
	struct sockaddr_in server_addr; 
	int socket_fd;
};

