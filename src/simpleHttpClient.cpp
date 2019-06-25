#include <iostream>
#include <string>

#include <unistd.h>

#include "simpleHttpClient.hpp"
using namespace std;

SimpleHttpClient::SimpleHttpClient(char *host, int port) {
	host_info = gethostbyname(host);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *)host_info->h_addr);
}

int SimpleHttpClient::tcpConnect() {
	if(host_info == NULL) {
		return -1;
	}
	
	if((socket_fd = socket(AF_INET,SOCK_STREAM, 0)) == -1){
		return -1;
	}

	if(connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1){
		return -1;
	}

	return socket_fd;
}

int SimpleHttpClient::tcpDisconnect() {
	return close(socket_fd);
}

int SimpleHttpClient::sendData(const char *buf, int len) {
	int ret;
	ret = send(socket_fd, buf, len, 0);
	return ret;
}

int SimpleHttpClient::recvData(char *buf, int len) {
	int ret;
	ret = recv(socket_fd, buf, len, 0);
	return ret;
}

