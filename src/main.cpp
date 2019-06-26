#include <iostream>
#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <plist/plist.h>

#include "simpleHttpClient.hpp"
#include "atv.hpp"

#define BUF_SIZE 4096

using namespace std;

string genAuthStep0Request(char *host, int port) {
	// POST /pair-pin-start HTTP/1.1
	// Host: 192.168.0.147:7000
	// Connection: keep-alive
	// User-Agent: AirPlay/320.20
	// Accept-Encoding: gzip, deflate
	// Accept: */*
	// Content-Length: 0
	// Content-Type: application/octet-stream

	ostringstream ostrStep0Request;
	string UrlStr = APPLE_URL_PAIR_PIN_START;

	ostrStep0Request << HTTP_REQUEST_METHOD_POST << " " << UrlStr << " " << HTTP_PROTOCOL_VERSION << "\r\n";
	ostrStep0Request << "Host: " << host << ":" << port << "\r\n";
	ostrStep0Request << "Connection: keep-alive" << "\r\n";
	ostrStep0Request << "User-Agent: AirPlay/320.20" << "\r\n";
	ostrStep0Request << "Accept-Encoding: gzip, deflate" << "\r\n";
	ostrStep0Request << "Accept: */*" << "\r\n";
	ostrStep0Request << "Content-Length: 0" << "\r\n";
	ostrStep0Request << "Content-Type: application/octet-stream" << "\r\n";
	ostrStep0Request << "\r\n";

	return ostrStep0Request.str();
}

string genAuthStep1Request(char *host, int port, unsigned char *plist_bin, uint32_t plist_bin_len) {
	// POST /pair-setup-pin HTTP/1.1
	// Host: 192.168.0.147:7000
	// Accept-Encoding: gzip, deflate
	// Accept: */*
	// User-Agent: Python/3.5 aiohttp/3.5.4
	// Content-Length: 85
	// Content-Type: application/octet-stream
	// plist binary data

	ostringstream ostrRequest;
	string UrlStr = APPLE_URL_PAIR_SETUP_PIN;

	ostrRequest << HTTP_REQUEST_METHOD_POST << " " << UrlStr << " " << HTTP_PROTOCOL_VERSION << "\r\n";
	ostrRequest << "Host: " << host << ":" << port << "\r\n";
	ostrRequest << "Accept-Encoding: gzip, deflate" << "\r\n";
	ostrRequest << "Accept: */*" << "\r\n";
	ostrRequest << "User-Agent: Python/3.5 aiohttp/3.5.4" << "\r\n";
	ostrRequest << "Content-Length: " << plist_bin_len << "\r\n";
	ostrRequest << "Content-Type: application/octet-stream" << "\r\n";
	ostrRequest << "\r\n";

	return ostrRequest.str().append((const char*)plist_bin, plist_bin_len);
}

plist_t genAuthStep1Plist(string user) {
	// XML format:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	// <plist version="1.0">
	// <dict>
	// 	<key>method</key>
	// 	<string>pin</string>
	// 	<key>user</key>
	// 	<string>3060A5F1D7593682</string>
	// </dict>
	// </plist>

	plist_t plist_item_pin = plist_new_string("pin");
	plist_t plist_item_user = plist_new_string(user.c_str());

	plist_t plist_root = plist_new_dict();
	plist_dict_set_item(plist_root, "method", plist_item_pin);
	plist_dict_set_item(plist_root, "user", plist_item_user);

	return plist_root;
}

int main() {
	bool debug = true;
	int ret = -1;

	char* host = "192.168.0.147";
	int port = 7000;
	char pResponseBuf[BUF_SIZE] = {0};

	string identifier = "FE32DDEADA833CE7"; // Hexadecimal representation of the 8 bytes binary data. (user name)
	char* pin = "1111"; // ASCII representation. (password)

	SimpleHttpClient httpClient = SimpleHttpClient(host, port);
	string strRequestData;

	ret = httpClient.tcpConnect();
	printf("Connect to %s:%d ", host, port);
	if(ret > -1) {
		printf("succeed\n");
	} else {
		printf("failed, ret = %d\n", ret);
		return -1;
	}

	// Request Apple TV to PIN pair (show PIN on Apple TV screen)
	strRequestData = genAuthStep0Request(host, port);
	ret = httpClient.sendData(strRequestData.c_str(), strRequestData.length());
	if(ret != 1) {
		printf("Send %d bytes data\n", ret);
		if(debug) {
			cout << "################################" << endl;
			cout << strRequestData << endl;
			cout << "################################" << endl << endl;
		}
	} else {
		printf("Send data failed, ret = %d\n", ret);
		return -1;
	}

	ret = httpClient.recvData(pResponseBuf, BUF_SIZE);
	if(ret != 1) {
		printf("Reveive %d bytes data\n", ret);
		if(debug) {
			cout << "################################" << endl;
			cout << pResponseBuf << endl;
			cout << "################################" << endl << endl;
		}
	} else {
		printf("Receive data failed, ret = %d\n", ret);
		return -1;
	}


	unsigned char *plist_bin;
	char *plist_xml;
	uint32_t plist_bin_len;
	uint32_t plist_xml_len;

	plist_t authStep1Plist = genAuthStep1Plist(identifier);
	plist_to_bin(authStep1Plist, (char**)&plist_bin, &plist_bin_len);
	plist_to_xml(authStep1Plist, (char**)&plist_xml, &plist_xml_len);
	printf("Generate %u bytes plist binary data\n", plist_bin_len);
	if(debug) {
		cout << "################################" << endl;
		for(int i = 0; i < plist_bin_len; i++) {
			printf("%02X ", plist_bin[i]);
			if((i+1)%16 == 0 && i != plist_bin_len-1)
				printf("\n");
		}
		printf("\n");
		cout << "################################" << endl << endl;

		printf("Generate %u bytes plist XML data\n", plist_xml_len);
		cout << "################################" << endl;
		cout << plist_xml;
		cout << "################################" << endl << endl;
	}

	strRequestData = genAuthStep1Request(host, port, plist_bin, plist_bin_len);
	ret = httpClient.sendData(strRequestData.c_str(), strRequestData.length());
	if(ret != 1) {
		printf("Send %d bytes data\n", ret);
		if(debug) {
			cout << "################################" << endl;
			cout << strRequestData << endl;
			cout << "################################" << endl << endl;
		}
	} else {
		printf("Send data failed, ret = %d\n", ret);
		return -1;
	}

	ret = httpClient.recvData(pResponseBuf, BUF_SIZE);
	if(ret != 1) {
		printf("Reveive %d bytes data\n", ret);
		if(debug) {
			cout << "################################" << endl;
			cout << pResponseBuf << endl;
			cout << "################################" << endl << endl;
		}
	} else {
		printf("Receive data failed, ret = %d\n", ret);
		return -1;
	}

	free(plist_bin);
	free(plist_xml);
	plist_free(authStep1Plist);

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
