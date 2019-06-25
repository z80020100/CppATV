#include <iostream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "simpleHttpClient.hpp"

using namespace std;

int main() {
	char* host = "192.168.0.147";
	int port = 7000;
	SimpleHttpClient httpClient = SimpleHttpClient(host, port);
	int ret = -1;

	ret = httpClient.tcpConnect();
	printf("Connect to %s:%d ", host, port);
	if(ret > -1) {
		printf("succeed\n");
	} else {
		printf("failed, ret = %d\n", ret);
		return -1;
	}

	ret = httpClient.tcpDisconnect();
	printf("Disconnect from %s:%d ", host, port);
	if(ret == 0) {
		printf("succeed\n");
	} else {
		printf("failed, ret = %d\n", ret);
		return -1;
	}

	return 0;
}
