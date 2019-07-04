#include <iostream>
#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <plist/plist.h>

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/donna.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
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
#include "ossl/osslsha512.hpp"
#include "ossl/osslmathimpl.hpp"
#include "ossl/osslrandom.hpp"

#include "simpleHttpClient.hpp"
#include "atv.hpp"

#define BUF_SIZE 4096

#define PRIVATE_KEY_LEN ed25519PrivateKey::SECRET_KEYLENGTH
#define PUBLIC_KEY_LEN  ed25519PrivateKey::PUBLIC_KEYLENGTH
#define SHARED_KEY_LEN  x25519::SHARED_KEYLENGTH
#define AES_GCM_TAG_LEN 16

using namespace std;
using namespace CryptoPP;
using namespace DragonSRP;
using namespace DragonSRP::Ossl;

using CryptoPP::AES;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Donna::curve25519_mult;
using CryptoPP::GCM;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

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

string genAuthStepRequest(char *host, int port, unsigned char *plist_bin, uint32_t plist_bin_len) {
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

string genVerifyStepRequest(char *host, int port, unsigned char *verify1_data, uint32_t verify1_data_len) {
	// POST /pair-verify HTTP/1.1
	// Host: 192.168.0.147:7000
	// Content-Type: application/octet-stream
	// Connection: keep-alive
	// User-Agent: AirPlay/320.20
	// Accept: */*
	// Accept-Encoding: gzip, deflate
	// Content-Length: 68
	// binary data

	ostringstream ostrRequest;
	string UrlStr = APPLE_URL_PAIR_VERIFY;

	ostrRequest << HTTP_REQUEST_METHOD_POST << " " << UrlStr << " " << HTTP_PROTOCOL_VERSION << "\r\n";
	ostrRequest << "Host: " << host << ":" << port << "\r\n";
	ostrRequest << "Content-Type: application/octet-stream" << "\r\n";
	ostrRequest << "Connection: keep-alive" << "\r\n";
	ostrRequest << "User-Agent: AirPlay/320.20" << "\r\n";
	ostrRequest << "Accept: */*" << "\r\n";
	ostrRequest << "Accept-Encoding: gzip, deflate" << "\r\n";
	ostrRequest << "Content-Length: " << verify1_data_len << "\r\n";

	ostrRequest << "\r\n";

	return ostrRequest.str().append((const char*)verify1_data, verify1_data_len);
}

string genPlayUrlRequest(char *host, int port, unsigned char *plist_bin, uint32_t plist_bin_len) {
	// POST /play HTTP/1.1
	// Host: 192.168.0.147:7000
	// Content-Type: application/x-apple-binary-plist
	// User-Agent: MediaControl/1.0
	// Accept-Encoding: gzip, deflate
	// Accept: */*
	// Content-Length: plist_bin_len
	// plist binary data

	ostringstream ostrRequest;
	string UrlStr = APPLE_URL_PLAY;

	ostrRequest << HTTP_REQUEST_METHOD_POST << " " << UrlStr << " " << HTTP_PROTOCOL_VERSION << "\r\n";
	ostrRequest << "Host: " << host << ":" << port << "\r\n";
	ostrRequest << "Content-Type: application/x-apple-binary-plist" << "\r\n";
	ostrRequest << "User-Agent: MediaControl/1.0" << "\r\n";
	ostrRequest << "Accept-Encoding: gzip, deflate" << "\r\n";
	ostrRequest << "Accept: */*" << "\r\n";
	ostrRequest << "Content-Length: " << plist_bin_len << "\r\n";

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

plist_t genAuthStep2Plist(const unsigned char* clientPublic, int clientPublicLen, const unsigned char* proof, int proofLen) {
	plist_t plist_item_client_public = plist_new_data(clientPublic, clientPublicLen);
	plist_t plist_item_proof = plist_new_data(proof, proofLen);

	plist_t plist_root = plist_new_dict();
	plist_dict_set_item(plist_root, "pk", plist_item_client_public);
	plist_dict_set_item(plist_root, "proof", plist_item_proof);

	return plist_root;
}

plist_t genAuthStep3Plist(const unsigned char* epk, int epkLen, const unsigned char* tag, int tagLen) {
	plist_t plist_item_epk = plist_new_data(epk, epkLen);
	plist_t plist_item_tag = plist_new_data(tag, tagLen);

	plist_t plist_root = plist_new_dict();
	plist_dict_set_item(plist_root, "epk", plist_item_epk);
	plist_dict_set_item(plist_root, "authTag", plist_item_tag);

	return plist_root;
}

plist_t genPlayUrlPlist(string url, int startPos){
	plist_t plist_item_url = plist_new_string(url.c_str());
	plist_t plist_item_pos = plist_new_string(to_string(startPos).c_str());

	plist_t plist_root = plist_new_dict();
	plist_dict_set_item(plist_root, "Content-Location", plist_item_url);
	plist_dict_set_item(plist_root, "Start-Position", plist_item_pos);

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

bytes getBinaryFromResp(char *respData, int bufLen) {
	bytes data;
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
	pResponseData = strstr(pBuf, "\r\n\r\n");
	pResponseData += 4;
	data = Conversion::array2bytes(pResponseData, responseDataLen);
	return data;
}

bytes genCurve25519Private(string strSeed) {
	bytes verifyPrivateKey = Conversion::hexstring2bytes(strSeed);
	verifyPrivateKey[0] &= 248;
	verifyPrivateKey[31] &= 127;
	verifyPrivateKey[31] |= 64;
	return verifyPrivateKey;
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

	strPin.clear();
	cout << "Enter PIN on screen: ";
	cin >> strPin;
	cin.ignore();

	// Step 1 Request
	unsigned char *plist_bin = NULL;
	char *plist_xml = NULL;
	uint32_t plist_bin_len = 0;
	uint32_t plist_xml_len = 0;

	plist_t authStep1Plist = genAuthStep1Plist(strIdentifier);
	plist_to_bin(authStep1Plist, (char**)&plist_bin, &plist_bin_len);
	plist_to_xml(authStep1Plist, (char**)&plist_xml, &plist_xml_len);
	plist_free(authStep1Plist);
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

	strRequestData = genAuthStepRequest(host, port, plist_bin, plist_bin_len);
	free(plist_bin);
	plist_bin = NULL;
	free(plist_xml);
	plist_xml = NULL;
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

	unsigned char *pkData = NULL, *saltData = NULL;
	uint64_t pkDataLen = 0, saltDataLen = 0;
	plist_t pkPlist = plist_dict_get_item(authStep1RespPlist, "pk");
	plist_t saltPlist = plist_dict_get_item(authStep1RespPlist, "salt");
	plist_get_data_val(pkPlist, (char**)&pkData, &pkDataLen);
	plist_get_data_val(saltPlist, (char**)&saltData, &saltDataLen);
	printf("pkData(B from server) is %ld bytes\n", pkDataLen);
	if(debug) {
		cout << "################################" << endl;
		for(int i = 0; i < pkDataLen; i++) {
			printf("%02X", pkData[i]);
			//if((i+1)%16 == 0 && i != pkDataLen-1)
				//printf("\n");
		}
		printf("\n");
		cout << "################################" << endl << endl;
	}
	printf("saltData is %ld bytes\n", saltDataLen);
	if(debug) {
		cout << "################################" << endl;
		for(int i = 0; i < saltDataLen; i++) {
			printf("%02X", saltData[i]);
			//if((i+1)%16 == 0 && i != saltDataLen-1)
				//printf("\n");
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
	cout << "Client public(A to server): ";
	Conversion::printBytes(A);
	cout << endl;
	cout << "################################" << endl << endl;

	// receive salt and B from server
	bytes salt = Conversion::array2bytes(saltData, saltDataLen); // resp['salt'] in pyatv/airplay/auth.py
	bytes B = Conversion::array2bytes(pkData, pkDataLen); // resp['pk'] in pyatv/airplay/auth.py. server public key
	//bytes salt = Conversion::hexstring2bytes("06f8f26e7a54b9e9d466afa772ec9d41");
	//bytes B = Conversion::hexstring2bytes("11eed8eaf3b7b4f99b405065f02c574468c064d2281dd21866af52beb376c1ba6096575fe840818b6f55b1e6cc6f818f2f6b26be3b1cf760174d94456e2b2201392af72c63bc15de3bdf0ceee6b2e181b30f3fa9f0587a3120180bcfac9c3331560815b142541bbd684b64519f9e6d9aa19b67b56e4470d3a4c97c217a4e5a001326ccc92915caa68a1683695a9942bf31459684b189e69eb65b60a2d471dc7ec1fe87ae2ec250244f0e76df6b92dc7a62f2b0671da40330f2110cbfa32bb7fcdf502b3e46e8e8d1bdb580dcac84cb121cefe362d3d1c8adccd472529f3d753854bceb55c54feb8e5d8f68bff43469f487dae1001e4f9ecb73173246feda1ee5");

	// send M1 to server
	bytes M1 = srpclient.getM1(salt, B, sca); // client_session_key_proof in pyatv/airplay/srp.py. exactly "M = H(H(N) XOR H(g) | H(U) | s | A | B | K)"
	cout << "################################" << endl;
	cout << "Proof(M1 to server): ";
	Conversion::printBytes(M1);
	cout << endl;
	cout << "################################" << endl << endl;
	free(pkData);
	pkData = NULL;
	free(saltData);
	saltData = NULL;

	bytes K = sca.getSessionKeyWithoutAuth();
	cout << "################################" << endl;
	cout << "Client session key(shared secret key): ";
	Conversion::printBytes(K);
	cout << endl;
	cout << "################################" << endl << endl;

	// Step 2 Request
	unsigned char *clientPkData, *proofData;
	int clientPkDataLen = -1, proofDataLen = -1;
	clientPkData = Conversion::bytes2array(A, &clientPkDataLen);
	proofData = Conversion::bytes2array(M1, &proofDataLen);
	plist_t authStep2Plist = genAuthStep2Plist(clientPkData, clientPkDataLen, proofData, proofDataLen);
	plist_to_bin(authStep2Plist, (char**)&plist_bin, &plist_bin_len);
	plist_to_xml(authStep2Plist, (char**)&plist_xml, &plist_xml_len);
	plist_free(authStep2Plist);
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

	strRequestData = genAuthStepRequest(host, port, plist_bin, plist_bin_len);
	free(plist_bin);
	plist_bin = NULL;
	free(plist_xml);
	plist_xml = NULL;
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

	// Step 2 Response
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

	// Calculate AES key from session key for authentication
	OsslSha512 sha512;
	bytes aesKeyHashInput = Conversion::string2bytes(APPLE_AUTH_AES_KEY_HASH_PREFIX);
	Conversion::append(aesKeyHashInput, K);
	bytes aesKey;
	aesKey.resize(sha512.outputLen());
	sha512.hash(&aesKeyHashInput[0], aesKeyHashInput.size(), &aesKey[0]);
	aesKey.resize(16);
	cout << "################################" << endl;
	cout << "AES key: ";
	Conversion::printBytes(aesKey);
	cout << endl;
	cout << "################################" << endl << endl;

	// Calculate AES IV from session key for authentication
	bytes aesIvHashInput = Conversion::string2bytes(APPLE_AUTH_AES_IV_HASH_PREFIX);
	Conversion::append(aesIvHashInput, K);
	bytes aesIv;
	aesIv.resize(sha512.outputLen());
	sha512.hash(&aesIvHashInput[0], aesIvHashInput.size(), &aesIv[0]);
	aesIv.resize(16);
	aesIv[aesIv.size()-1]++;
	cout << "################################" << endl;
	cout << "AES IV: ";
	Conversion::printBytes(aesIv);
	cout << endl;
	cout << "################################" << endl << endl;

	// Encrypt client public key via GCM AES, ciphertext with tag
	string ciphertext;
	string plaintext((const char*)public_key, PUBLIC_KEY_LEN);
	GCM<AES>::Encryption enc;
	enc.SetKeyWithIV(&aesKey[0], aesKey.size(), &aesIv[0], aesIv.size());

	AuthenticatedEncryptionFilter aef(enc,
		new StringSink(ciphertext)
	);

	aef.Put(plaintext.data(), plaintext.size());
	aef.MessageEnd();

	bytes epk, tag;
	int epkLen = ciphertext.length() - AES_GCM_TAG_LEN;
	int tagLen = AES_GCM_TAG_LEN;
	epk = Conversion::array2bytes(ciphertext.c_str(), epkLen);
	cout << "################################" << endl;
	cout << "EPK: ";
	Conversion::printBytes(epk);
	cout << endl;
	cout << "################################" << endl << endl;

	tag = Conversion::array2bytes(ciphertext.c_str() + epkLen, tagLen);
	cout << "################################" << endl;
	cout << "Tag: ";
	Conversion::printBytes(tag);
	cout << endl;
	cout << "################################" << endl << endl;

	// Step 3 Request
	unsigned char *epkData, *tagData;
	int epkDataLen = -1, tagDataLen = -1;
	epkData = Conversion::bytes2array(epk, &epkDataLen);
	tagData = Conversion::bytes2array(tag, &tagDataLen);
	plist_t authStep3Plist = genAuthStep3Plist(epkData, epkDataLen, tagData, tagDataLen);
	plist_to_bin(authStep3Plist, (char**)&plist_bin, &plist_bin_len);
	plist_to_xml(authStep3Plist, (char**)&plist_xml, &plist_xml_len);
	plist_free(authStep3Plist);
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

	strRequestData = genAuthStepRequest(host, port, plist_bin, plist_bin_len);
	free(plist_bin);
	plist_bin = NULL;
	free(plist_xml);
	plist_xml = NULL;
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

	// Step 3 Response
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

	// Verification: calculate verification key pair
	bytes clientVerifyPrivate = genCurve25519Private(strSeed);
	cout << "################################" << endl;
	cout << "Client verify private: ";
	Conversion::printBytes(clientVerifyPrivate);
	cout << endl;
	cout << "################################" << endl << endl;

	bytes clientVerifyPublic;
	clientVerifyPublic.resize(PUBLIC_KEY_LEN);
	ret = curve25519_mult(&clientVerifyPublic[0], &clientVerifyPrivate[0]);
	if(ret == 0) {
		cout << "################################" << endl;
		cout << "Client verify public: ";
		Conversion::printBytes(clientVerifyPublic);
		cout << endl;
		cout << "################################" << endl << endl;
	} else {
		printf("Calculate verify public key failed, ret = %d\n", ret);
		return -1;
	}

	// Verification Step 1 Request
	bytes clientAuthPublic = Conversion::array2bytes(public_key, PUBLIC_KEY_LEN);
	bytes verify1Data;
	verify1Data.push_back(0x01);
	verify1Data.push_back(0x00);
	verify1Data.push_back(0x00);
	verify1Data.push_back(0x00);
	Conversion::append(verify1Data, clientVerifyPublic);
	Conversion::append(verify1Data, clientAuthPublic);
	cout << "################################" << endl;
	cout << "Client verify step 1 data: ";
	Conversion::printBytes(verify1Data);
	cout << endl;
	cout << "################################" << endl << endl;

	strRequestData = genVerifyStepRequest(host, port, &verify1Data[0], verify1Data.size());
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

	// Verification Step 1 Response
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
	bytes verify1RespData = getBinaryFromResp(pResponseBuf, BUF_SIZE);
	//bytes verify1RespData = Conversion::hexstring2bytes("064e1654f604e59bd15a883bfe80e9fefa15f8da0df92aae1d1712879ce92c71aeac5c5ba7f4b730628ca2a8094d7f6faf7a255873cf0d58fc20068087951717f6bfec43219a9413dfbd700099c67164f34d843f047ddadc5667d44e969907e1");
	cout << "################################" << endl;
	cout << "Client verify step 1 resp data: ";
	Conversion::printBytes(verify1RespData);
	cout << endl;
	cout << "################################" << endl << endl;

	bytes serverVerifyPublic = Conversion::array2bytes(&verify1RespData[0], PUBLIC_KEY_LEN);
	cout << "################################" << endl;
	cout << "Server verify public: ";
	Conversion::printBytes(serverVerifyPublic);
	cout << endl;
	cout << "################################" << endl << endl;

	int serverRespDataLen = verify1RespData.size() - PUBLIC_KEY_LEN;
	bytes serverRespData = Conversion::array2bytes(&verify1RespData[0] + PUBLIC_KEY_LEN, serverRespDataLen);
	cout << "################################" << endl;
	cout << "Server response data in verify step 1: ";
	Conversion::printBytes(serverRespData);
	cout << endl;
	cout << "################################" << endl << endl;

	// Generate a shared secret key for verification
	bytes authShared;
	authShared.resize(SHARED_KEY_LEN);
	ret = curve25519_mult(&authShared[0], &clientVerifyPrivate[0], &serverVerifyPublic[0]);
	if(ret == 0) {
		cout << "################################" << endl;
		cout << "Verify shared key: ";
		Conversion::printBytes(authShared);
		cout << endl;
		cout << "################################" << endl << endl;
	} else {
		printf("Calculate verify shared key failed, ret = %d\n", ret);
		return -1;
	}

	// Calculate AES key from shared key for verification
	bytes aesKeyVerifyHashInput = Conversion::string2bytes(APPLE_VERIFY_AES_KEY_HASH_PREFIX);
	Conversion::append(aesKeyVerifyHashInput, authShared);
	bytes aesKeyVerify;
	aesKeyVerify.resize(sha512.outputLen());
	sha512.hash(&aesKeyVerifyHashInput[0], aesKeyVerifyHashInput.size(), &aesKeyVerify[0]);
	aesKeyVerify.resize(16);
	cout << "################################" << endl;
	cout << "AES key for verification: ";
	Conversion::printBytes(aesKeyVerify);
	cout << endl;
	cout << "################################" << endl << endl;

	// Calculate AES IV from shared key for verification
	bytes aesIvVerifyHashInput = Conversion::string2bytes(APPLE_VERIFY_AES_IV_HASH_PREFIX);
	Conversion::append(aesIvVerifyHashInput, authShared);
	bytes aesIvVerify;
	aesIvVerify.resize(sha512.outputLen());
	sha512.hash(&aesIvVerifyHashInput[0], aesIvVerifyHashInput.size(), &aesIvVerify[0]);
	aesIvVerify.resize(16);
	cout << "################################" << endl;
	cout << "AES IV for verification: ";
	Conversion::printBytes(aesIvVerify);
	cout << endl;
	cout << "################################" << endl << endl;

	// Sign public key
	bytes msg, signature;
	msg.clear();
	signature.clear();
	Conversion::append(msg, clientVerifyPublic);
	Conversion::append(msg, serverVerifyPublic);
	size_t siglen = signer.MaxSignatureLength();
	signature.resize(siglen);
	AutoSeededRandomPool prng;
	siglen = signer.SignMessage(prng, (const byte*)&msg[0], msg.size(), (byte*)&signature[0]);
	signature.resize(siglen);
	cout << "################################" << endl;
	cout << "Signed public key (client + server) for verification: ";
	Conversion::printBytes(signature);
	cout << endl;
	cout << "################################" << endl << endl;

	// Generate signature via encrypting server response data + signed public key with CTR AES
	ciphertext.clear();
	plaintext.clear();
	plaintext.append(&serverRespData[0], serverRespData.size());
	plaintext.append(&signature[0], signature.size());
	CTR_Mode<AES>::Encryption encAesCtr;
	encAesCtr.SetKeyWithIV(&aesKeyVerify[0], aesKeyVerify.size(), &aesIvVerify[0], aesIvVerify.size());
	StringSource(plaintext, true,
		new StreamTransformationFilter(encAesCtr,
			new StringSink(ciphertext)
		) // StreamTransformationFilter
	); // StringSource
	// Apple use the last 64 bytes as signature
	int offset = ciphertext.size() - 64;
	bytes finalSignature = Conversion::array2bytes(ciphertext.c_str() + offset, 64); 
	cout << "################################" << endl;
	cout << "Final signature for verification: ";
	Conversion::printBytes(finalSignature);
	cout << endl;
	cout << "################################" << endl << endl;

	// Verification Step 2 Request
	bytes verify2Data;
	verify2Data.push_back(0x00);
	verify2Data.push_back(0x00);
	verify2Data.push_back(0x00);
	verify2Data.push_back(0x00);
	Conversion::append(verify2Data, finalSignature);
	cout << "################################" << endl;
	cout << "Client verify step 2 data: ";
	Conversion::printBytes(verify2Data);
	cout << endl;
	cout << "################################" << endl << endl;

	strRequestData = genVerifyStepRequest(host, port, &verify2Data[0], verify2Data.size());
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

	// Verification Step 2 Response
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

	// Request Apple TV to play a URL
	plist_t playUrlPlist = genPlayUrlPlist("https://p-events-delivery.akamaized.net/18oijbasfvuhbfsdvoijhbsdfvljkb6/m3u8/hls_vod_mvp.m3u8", 0);
	plist_to_bin(playUrlPlist, (char**)&plist_bin, &plist_bin_len);

	strRequestData = genPlayUrlRequest(host, port, plist_bin, plist_bin_len);
	free(plist_bin);
	plist_bin = NULL;
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

	// Apple TV response for play URL request
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

	while(true){
		sleep(1);
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
