#include <iostream>
#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <plist/plist.h>

#include <cryptopp/xed25519.h>

#include "dsrp/srpclient.hpp"
#include "dsrp/srpclientauthenticator.hpp"
#include "dsrp/user.hpp"
#include "dsrp/ng.hpp"
#include "dsrp/dsrpexception.hpp"
#include "dsrp/conversionexception.hpp"
#include "dsrp/usernotfoundexception.hpp"
#include "dsrp/conversion.hpp"

#include "ossl/osslsha1.hpp"
#include "ossl/osslmathimpl.hpp"
#include "ossl/osslrandom.hpp"

#include "simpleHttpClient.hpp"
#include "atv.hpp"

#define BUF_SIZE 4096

#define PRIVATE_KEY_LEN ed25519PrivateKey::SECRET_KEYLENGTH
#define PUBLIC_KEY_LEN  ed25519PrivateKey::PUBLIC_KEYLENGTH

using namespace std;
using namespace CryptoPP;
using namespace DragonSRP;
using namespace DragonSRP::Ossl;

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

plist_t getPlistFromResp(char *respData, int bufLen) {
	plist_t plist_root;
	char pBuf[BUF_SIZE] = {0};
	char *pResponseData;
	char *pResponseDataLen;
	uint32_t responseDataLen;

	memcpy(pBuf, respData, BUF_SIZE);
	pResponseDataLen = strstr(pBuf, "Content-Length:");
	pResponseDataLen = strtok(pResponseDataLen, " ");
	pResponseDataLen = strtok(NULL, " \r\n");
	responseDataLen = atoi(pResponseDataLen);
	printf("Response data is %d bytes (binary format)\n", responseDataLen);

	memcpy(pBuf, respData, BUF_SIZE);
	pResponseData = strstr(pBuf, "bplist00");
	plist_from_bin((const char*)pResponseData, responseDataLen, &plist_root);
	return plist_root;
}

int main() {
	bool debug = true;
	int ret = -1;

	char* host = "192.168.0.147";
	int port = 7000;
	char pResponseBuf[BUF_SIZE] = {0};
	char pBuf[BUF_SIZE] = {0};

	string strIdentifier = "3060A5F1D7593682"; // Hexadecimal representation of the 8 bytes binary data. (user name)
	string strPin = "1111"; // ASCII representation. (password)
	string strSeed = "8C43FEBD67F4DBB3B2C7FFBB1B7C1E580512823E3B759259E8CB33382A5DA60A"; // It's ed25519 private key exactly, hexadecimal representation
	byte binSeed[PRIVATE_KEY_LEN] = {0}; // ed25519 private key, binary data, 32 bytes
	unsigned char *private_key;
	unsigned char *public_key;
	for(int i = 0; i < PRIVATE_KEY_LEN; i++) {
		sscanf(strSeed.c_str()+(i*2), "%2hhx", binSeed+i); // Hex string to byte array
	}

	// Use Crypto++ to generate ED25519 key pair. More information: https://www.cryptopp.com/wiki/Ed25519
	printf("Generate authentication key pair:\n%d private key + %d bytes public key\n", PRIVATE_KEY_LEN, PUBLIC_KEY_LEN);
	ed25519::Signer signer(binSeed);
	const ed25519PrivateKey& privKey = dynamic_cast<const ed25519PrivateKey&>(signer.GetPrivateKey());
	const Integer& x = privKey.GetPrivateExponent(); // big-endian Integer()
	cout << "################################" << endl;
	std::cout << "Private=";
	//std::cout << hex << x << std::endl;
	private_key = (unsigned char*)privKey.GetPrivateKeyBytePtr(); // little-endian byte array
	for(int i = 0; i < PRIVATE_KEY_LEN; i ++){
		printf("%02X", private_key[i]);
	}
	cout << endl;

	ed25519::Verifier verifier(signer);
	const ed25519PublicKey& pubKey = dynamic_cast<const ed25519PublicKey&>(verifier.GetPublicKey());
	const Integer& y = pubKey.GetPublicElement(); // big-endian Integer()
	std::cout << "Public =";
	//std::cout << std::hex << y << std::endl;
	public_key = (unsigned char*)pubKey.GetPublicKeyBytePtr(); // little-endian byte array
	for(int i = 0; i < PUBLIC_KEY_LEN; i ++){
		printf("%02X", public_key[i]);
	}
	cout << endl;
	cout << "################################" << endl << endl;

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

	memset(pResponseBuf, 0, BUF_SIZE);
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

	// Step 1 Request
	unsigned char *plist_bin;
	char *plist_xml;
	uint32_t plist_bin_len;
	uint32_t plist_xml_len;

	plist_t authStep1Plist = genAuthStep1Plist(strIdentifier);
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
	free(plist_bin);
	free(plist_xml);
	ret = httpClient.sendData(strRequestData.c_str(), strRequestData.length());
	plist_free(authStep1Plist);
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

	// Step 1 Response
	memset(pResponseBuf, 0, BUF_SIZE);
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

	plist_t authStep1RespPlist = getPlistFromResp(pResponseBuf, BUF_SIZE);
	if(debug){
		plist_to_xml(authStep1RespPlist, (char**)&plist_xml, &plist_xml_len);
		cout << "Convert to XML format to read" << endl;
		cout << "################################" << endl;
		cout << plist_xml;
		cout << "################################" << endl << endl;
		free(plist_xml);
	}

	unsigned char *pkData, *saltData;
	uint64_t pkDataLen = -1, saltDataLen = -1;
	plist_t pkPlist = plist_dict_get_item(authStep1RespPlist, "pk");
	plist_t saltPlist = plist_dict_get_item(authStep1RespPlist, "salt");
	plist_get_data_val(pkPlist, (char**)&pkData, &pkDataLen);
	plist_get_data_val(saltPlist, (char**)&saltData, &saltDataLen);
	printf("pkData is %ld bytes\n", pkDataLen);
	if(debug) {
		cout << "################################" << endl;
		for(int i = 0; i < pkDataLen; i++) {
			printf("%02X ", pkData[i]);
			if((i+1)%16 == 0 && i != pkDataLen-1)
				printf("\n");
		}
		printf("\n");
		cout << "################################" << endl << endl;
	}
	printf("saltData is %ld bytes\n", saltDataLen);
	if(debug) {
		cout << "################################" << endl;
		for(int i = 0; i < saltDataLen; i++) {
			printf("%02X ", saltData[i]);
			if((i+1)%16 == 0 && i != saltDataLen-1)
				printf("\n");
		}
		printf("\n");
		cout << "################################" << endl << endl;
	}

	// Secure Remote Password (SRP6a)
	OsslSha1 hash;
	OsslRandom random;
	Ng ng = Ng::predefined(2048);
	OsslMathImpl math(hash, ng);
	SrpClient srpclient(math, random, false);

	cout << "Use fixed ID and PIN for develop" << endl;
	cout << "################################" << endl;
	cout << "ID : " << strIdentifier << endl;
	cout << "PIN: " << strPin << endl;
	cout << "################################" << endl << endl;
	bytes username = Conversion::string2bytes(strIdentifier);
	bytes password = Conversion::string2bytes(strPin);
	bytes clientPrivate = Conversion::hexstring2bytes(strSeed);
	SrpClientAuthenticator sca = srpclient.getAuthenticator(username, password, clientPrivate);

	// send username and A to server
	bytes A = sca.getA(); // client_public in pyatv/airplay/srp.py. exactly "A = g^a % N"
	cout << "################################" << endl;
	cout << "Client public: ";
	Conversion::printBytes(A);
	cout << endl;
	cout << "################################" << endl << endl;

	free(pkData);
	free(saltData);

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
