// DNSHomework2.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <time.h>
#include<vector>
#include <stdio.h>
#include <stdlib.h>
#include "DNSHomework2.h"

#pragma comment(lib,"WS2_32")

//====================================================================================================================== =
//TODO
//-do authority and the other one
//-check for differences between type A and type PTR, I think pkt_size needs ot be readjusted for the in_addr.arpa part
//-error checking and all that
//=======================================================================================================================


using namespace std;

#define _CRT_SECURE_NO_WARNINGS
#define MAX_ATTEMPTS 3
#define MAX_DNS_SIZE 512

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 

/* query classes */
#define DNS_INET 1

/* result codes */
#define DNS_OK 0 /* success */
#define DNS_FORMAT 1 /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2 /* can�t find authority nameserver */
#define DNS_ERROR 3 /* no DNS entry */
#define DNS_NOTIMPL 4 /* not implemented */
#define DNS_REFUSED 5 /* server refused the query */

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */
//
#pragma pack(push,1) // sets struct padding/alignment to 1 byte
class QueryHeader {
public:
	USHORT qType;
	USHORT qClass;
};
class FixedDNSheader {
public:
	USHORT ID;
	USHORT flags;
	USHORT questions;
	USHORT answers;
	USHORT authority;
	USHORT additional;
};
class DNSanswerHdr {
public:
	u_short type;
	u_short qclass;
	u_int ttl;
	u_short len;
};
#pragma pack(pop)
struct parseReturn {
	int pos;
	string result;
};

//found online
vector<string> SplitString(string s) {
	vector<string> v;
	string temp = "";
	for (int i = 0; i < s.length(); ++i) {
		if (s[i] == '.') {
			v.push_back(temp);
			temp = "";
		}
		else {
			temp.push_back(s[i]);
		}
	}
	v.push_back(temp);
	return v;
}
string reverseLookup(char* hostname) {
	vector<string> split_host = SplitString(hostname);
	reverse(split_host.begin(), split_host.end());
	string host = "";

	for (int i = 0; i < split_host.size(); i++) {
		host += split_host[i];
		host += ".";
	}
	host += "in-addr.arpa\0";
	return host;
}
void buildQuestion(char* buf, char* hostname) {
	int tracker = 0;
	vector<string> split_host = SplitString(hostname);
	for (int i = 0; i < split_host.size(); i++) {
		buf[tracker] = split_host[i].length();
		tracker++;
		strncpy(buf + tracker, split_host[i].c_str(), split_host[i].length());
		tracker += split_host[i].length();
	}
	buf[tracker++] = '\0';
}

char* constructQuery(char* hostname, int type, string host) {
	int pkt_size = strlen(hostname) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
	char* buf = new char[pkt_size];
	FixedDNSheader* fdh = (FixedDNSheader*)buf;
	QueryHeader* qh = (QueryHeader*)(buf + pkt_size - sizeof(QueryHeader));
	char* question = buf+sizeof(FixedDNSheader);
	//build fixed header
	srand(time(NULL));
	int id = rand() % 1000 + 1;
	fdh->ID = htons(id);
	fdh->flags = htons(DNS_QUERY | DNS_STDQUERY | DNS_RD);
	fdh->questions = htons(1);
	fdh->additional = htons(0);
	fdh->answers = htons(0);
	fdh->authority = htons(0);
	
	qh->qType = htons(type);
	qh->qClass = htons(DNS_INET);

	buildQuestion(buf+sizeof(FixedDNSheader), hostname);
	
	printf("Lookup:    %s\nQuery:     %s, type %i, TXID 0x%.4X\n", host.c_str(), hostname, (int)htons(qh->qType), (int)htons(fdh->ID));
	return buf;
}

void printMem(char* tracker) {
	for (int i = 0; i < 24; i++) {
		printf("tracker[%d] = %.2X\n", i, tracker[i]);
	}
}


int calculateJump(char* response, char* tracker, int bytes) {
	
	//printf("tracker[0]: %.2X", tracker[0]);
	if ((unsigned char)tracker[0] >= 0xc0)
	{
		int off = (((unsigned char)tracker[0] & 0x3f) << 8) + (unsigned char)tracker[1];	
		char* loop_check = response + off;
		if (off > 0 && off < 12) {
			cout << "++\tinvalid record: jump into fixed header\n";
			exit(EXIT_FAILURE);
		}

		if (tracker + 2 - response > bytes) {
			cout << "++\tinvalid record: truncated jump offset\n";
			exit(EXIT_FAILURE);
		}
		if ((unsigned char)loop_check[0] >= 0xc0)
		{
			cout << "++\tinvalid record: jump loop\n";
			exit(EXIT_FAILURE);
		}
		
		return off;
	}
	else {	//not compressed
		return 0;
	}

	
}

parseReturn parse(char* buf, char* tracker, int bytes) {
	string str;
	int pos = 0;
	while (true) {
		if (tracker[0] == 0xFFFFFFC0) {
			int offset = calculateJump(buf,tracker, bytes);
			if (tracker+offset-buf > bytes) {
				cout << "++\tinvalid record: jump beyond packet boundary\n";
				exit(EXIT_FAILURE);
			}
			parseReturn iterim = parse(buf, buf + offset, bytes);
			str += iterim.result;
			tracker += 2;
			pos += 2;
			break;
			
		}
		else {
			int size = tracker[0];
			if (size == 0) {
				tracker++;
				pos++;
				break;
			}
			tracker++;
			pos += 1;
			char temp[256];
			memcpy(temp, tracker, size);
			if (tracker - buf + size >= bytes) {
				cout << "++\tinvalid record: truncated name\n";
				exit(EXIT_FAILURE);
			}
			temp[size] = 0;
			tracker += size;
			pos += size;
			str += temp;
			if (tracker[1] != 0) {
				str += ".";
			}
		}
	}
	
	parseReturn ret;
	ret.result = str;
	ret.pos = pos;
	return ret;
}

char* parseQuestions(char* response, char* tracker, FixedDNSheader* fdh, int bytes) {
	tracker += sizeof(FixedDNSheader);
	printf("\t============ [questions] ============\n");
	for (int i = 0; i < htons(fdh->questions); i++) {
		parseReturn result = parse(response, tracker, bytes);
		tracker += result.pos;
		string hostname = result.result;
		QueryHeader* qh = (QueryHeader*)tracker;
		tracker += sizeof(QueryHeader);
		cout << "\t\t"<<hostname;
		printf(" type %d class %d\n", (int)htons(qh->qType), (int)htons(qh->qClass));
	}

	return tracker;
}


char* parseRR(char* response, char* tracker, FixedDNSheader* fdh, string RRtype, int bytes) {
	int rrcount = 0;
	if (RRtype == "answers") {
		rrcount = htons(fdh->answers);
	}
	else if (RRtype == "authority") {
		rrcount = htons(fdh->authority);
	}
	else if (RRtype == "additional") {
		rrcount = htons(fdh->additional);
	}
	else {
		cout << "you misspelled it idiot" << endl;
		return nullptr;
	}
	if (rrcount == 0) {
		return tracker;
	}
	printf("\t============ [%s] ============\n", RRtype.c_str());
	for (int i = 0; i < rrcount; i++) {
		if (tracker - response >= bytes) {
			cout << "++\tinvalid record: not enough records\n";
			return nullptr;
		}
		parseReturn result = parse(response, tracker, bytes);
		tracker += result.pos;
		string query = result.result;

		if (tracker + sizeof(DNSanswerHdr) - response > bytes) {
			cout << "++\tinvalid record: truncated fixed RR header\n";
			return nullptr;
		}
		//tracker--;
		DNSanswerHdr* answerHDR = (DNSanswerHdr*)tracker;
		tracker += sizeof(DNSanswerHdr);

		

		string class_string;
		string ans;
		bool valid = true;
		int aClass = htons(answerHDR->type);
		if (tracker + (int)htons(answerHDR->len) - response > bytes) {
			cout << "++\tinvalid record: RR value strethces the answer beyond packet\n";
			return nullptr;
		}
		switch (aClass) {
		case 1:
			class_string = "A";
			char saddr[16];
			sprintf(saddr, "%d.%d.%d.%d", (unsigned char)tracker[0], (unsigned char)tracker[1], (unsigned char)tracker[2], (unsigned char)tracker[3]);
			ans = saddr;
			tracker += 4;
			//tracker++;
			break;
		case 2:
			class_string = "NS";
			result = parse(response, tracker, bytes);
			tracker += result.pos;
			ans = result.result;
			break;
		case 5:
			class_string = "CNAME";
			result = parse(response, tracker, bytes);
			tracker += result.pos;
			ans = result.result;
			break;
		case 12:
			class_string = "PTR";
			result = parse(response, tracker, bytes);
			tracker += result.pos;
			ans = result.result;
			break;
		default:
			valid = false;
		}
		
		//cout << "class = " << aClass << " TTL = " << (int)htons(answerHDR->ttl) << "len = " << htons(answerHDR->len) << endl;
		if (valid) {
			printf("\t\t%s %s %s TTL = %d\n", query.c_str(), class_string.c_str(), ans.c_str(), (int)htons(answerHDR->ttl));
		}
		//tracker--;
	}
	return tracker;

}



bool checkFDHerrors(FixedDNSheader* original, FixedDNSheader* response) {

	if (htons(original->ID) != htons(response->ID)) {
		printf("\t++\t invalid reply: TXID mismatch, sent 0x%.4x, received 0x%.4X\n", htons(original->ID), htons(response->ID));
		return false;
	}
	int rcode = (htons(response->flags) & 0x000f);
	if ( rcode== 0) {
		printf("\tsucceeded with Rcode = %d\n", rcode);
	}
	else {
		printf("\tfailed with Rcode %d\n", rcode);
		return false;
	}



	return true;
}

int main(int argc, char* argv[]){
	if (argc != 3) {
		cout << "Invalid input arguments\nFormat: ./hw2.exe <hostname/IP> <DNS IP>\n";
		return 0;
	}
	char* hostname_arg = argv[1];
	char* dns_ip = argv[2];
	
	char input_hostname[MAX_DNS_SIZE];
	//char input_hostname[] = "www.google.com\0";
	//char* input_hostname = new char[MAX_DNS_SIZE]; 
	////string host = "12.190.0.107\0";
	////string host = "google.c\0";
	//string host = "random5.irl\0";
	//strcpy(input_hostname, host.c_str());

	//char* dns_ip = argv[2];
	//char dns_ip[] = "127.0.0.1\0";
	int type;
	if (inet_addr(hostname_arg) != INADDR_NONE) {
		type = DNS_PTR;
		string new_host = reverseLookup(hostname_arg);
		strcpy(input_hostname, new_host.c_str());
	}
	else {
		type = DNS_A;
		strcpy(input_hostname, hostname_arg);
	}
	//Build DNS query packet
	int pkt_size = strlen(input_hostname) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
	char* buf = constructQuery(input_hostname, type, hostname_arg);
	FixedDNSheader* fdh = (FixedDNSheader*)buf;
	cout << "Server:    " << dns_ip << endl;
	cout << "********************************" << endl;


	//Setup socket
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) > 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET){
		printf("socket() generated error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		cout << "Error binding socket: " << WSAGetLastError() << endl;
		return 0;
	}
		
	
	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(dns_ip); // server�s IP
	remote.sin_port = htons(53); // DNS port on server

	char* response_buf = new char[MAX_DNS_SIZE];
	struct sockaddr_in response;
	int sockaddr_size = sizeof(struct sockaddr_in);
	int count = 0;
	while (count++ < MAX_ATTEMPTS)
	{
		clock_t start, end;
		start = clock();
		cout << "Attempt " << count << " with " << pkt_size << " bytes...";
		if (sendto(sock, buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
			cout << "Error sending request: " << WSAGetLastError() << endl;
			return 0;
		}
			// get ready to receive
		fd_set fd;
		FD_ZERO(&fd); // clear the set
		FD_SET(sock, &fd); // add your socket to the set
		struct timeval tp;
		tp.tv_sec = 10;
		tp.tv_usec = 0;
		int available = select(0, &fd, NULL, NULL, &tp);
		int bytes = 0;
		if (available > 0)
		{
			bytes = recvfrom(sock, response_buf, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &sockaddr_size);
			if (bytes ==SOCKET_ERROR) {
				cout<<"Recvfrom Error: " << WSAGetLastError() << endl;
				return 0;
			}
			
			// check if this packet came from the server to which we sent the query earlier
			if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port) {
				cout << "Bogus reply: compaining\n";
				break;
			}
			char* tracker = response_buf;
			end = clock();
			int response_time = ((end - start) * 1000) / CLOCKS_PER_SEC;

			/*if (strstr(response_buf, buf) == NULL) {
				printf("Response FDH not found\n");
				return 0;
			}*/
			FixedDNSheader* fdh_response = (FixedDNSheader*)response_buf;
			if (fdh_response == NULL) {
				printf("Error gettings response FDH header\n");
				return 0;
			}


			printf("response in %d ms with %d bytes\n", response_time, bytes);
			if (bytes < sizeof(FixedDNSheader)) {
				cout << "\t\t++\t invalid reply: packet smaller than fixed DNS header\n";
				return 0;
			}
			printf("\tTXID 0x%.4X flags 0x%.4X questions %d answers %d authority %d additional %d\n", htons(fdh_response->ID), htons(fdh_response->flags), (int)htons(fdh_response-> questions), (int)htons(fdh_response-> answers), (int)htons(fdh_response-> authority), (int)htons(fdh_response->additional));
			

			if (!checkFDHerrors(fdh, fdh_response)) {
				return 0;
			}
			/*int currPos = parseQuestions(tracker, input_hostname, fdh);
			tracker += currPos;*/
			

			tracker = parseQuestions(response_buf, tracker, fdh_response, bytes);
			//tracker += pkt_size - sizeof(FixedDNSheader)+1;
			
			tracker = parseRR(response_buf, tracker, fdh_response, "answers", bytes);
			if (tracker == nullptr) {
				return 0;
			}
			tracker = parseRR(response_buf, tracker, fdh_response, "authority", bytes);
			if (tracker == nullptr) {
				return 0;
			}
			tracker = parseRR(response_buf, tracker, fdh_response, "additional", bytes);
			if (tracker == nullptr) {
				return 0;
			}
			
			//printf("tracker = %X\n", tracker);

			//currPos = parseAuthority(tracker, response_buf, fdh_response, bytes);

			//currPos = parseAnswers(response, currPos);
				// parse questions and arrive to the answer section
				
				// suppose off is the current position in the packet
				//FixedRR * frr = (FixedRR*)(buf + off);
			// read frr->len and other fields
			

			break;
		}
		else if (available < 0) {
			printf("failed with %d on recv\n", WSAGetLastError());
			return 0;
		}
		// error checking here
		cout << " timeout in 10000 ms" << endl;
	}
	WSACleanup();
	delete buf;
	

	return 0;
}

