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
void printArray(char* ptr, int len, int yes)
{

	cout << "\t\t\tHERE" << endl;
	for (int jjj = 0; jjj < len; jjj++)
		printf("\t\tj %d c %c x %02x\n", jjj, (unsigned char)ptr[jjj], ptr[jjj]);
	cout << endl;

}





int calculateJump(char* response, char* tracker) {
	
	//printf("tracker[0]: %.2X", tracker[0]);
	if ((unsigned char)tracker[0] >= 0xc0)
	{
		cout << "compressed\n";
		int off = (((unsigned char)tracker[0] & 0x3f) << 8) + (unsigned char)tracker[1];	
		char* loop_check = response + off;
		if ((unsigned char)loop_check[0] >= 0xc0)
		{
			printf("++\tinvalid record: jump loop\n");
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		
		return off;
	}
	else {	//not compressed
		cout << "not compressed\n";
		return 0;
	}

	
}
parseReturn parse(char* buf, char* tracker) {
	string str;
	int pos = 0;
	while (tracker[0] != 0) {
		if (tracker[0] == 0xC0) {
			int offset = calculateJump(buf,tracker);
			parseReturn iterim = parse(buf, tracker + offset);
			str += iterim.result;
			pos += 2;
		}
		else {
			int size = tracker[0];
			tracker++;
			pos += 1;
			char temp[256];
			memcpy(temp, tracker, size);
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

char* parseQuestions(char* response, char* tracker, FixedDNSheader* fdh) {
	for (int i = 0; i < htons(fdh->questions); i++) {
		parseReturn result = parse(response, tracker);
		tracker += result.pos;
		string hostname = result.result;
		QueryHeader* qh = (QueryHeader*)tracker;
		tracker += sizeof(QueryHeader);
		printf("\t\t%s type %d class %d\n", hostname, (int)htons(qh->qType), (int)htons(qh->qClass));
	}
	return tracker;
}
//int parseQuestions(char* response, char* hostname, FixedDNSheader* fdh) {
//	int tracker = 0;
//	if (fdh->questions == 0) {
//		return 0;
//	}
//	response = response + sizeof(FixedDNSheader);
//	tracker += sizeof(FixedDNSheader);
//
//	printf("\t============ [questions] ============\n");
//
//	for (int i = 0; i < htons(fdh->questions); i++) {
//		cout << "\t      ";
//		char* index = response;
//		int bytes = 0;
//		while (true) {
//			int string_size = response[0];
//			response += 1;
//			tracker++;
//			char* slice = new char[string_size];
//
//			memcpy(slice, response, (int)string_size);
//			slice[string_size] = '\0';
//			tracker += string_size;
//			printf("%s", slice);
//			response += string_size;
//			if (response[0] != 0) {
//				cout << ".";
//			}
//			else {
//				tracker++;
//				response++;
//				break;
//			}
//		}
//		QueryHeader* qh = (QueryHeader*)(response);
//		printf(" type %d class %d\n", (int)htons(qh->qType), (int)htons(qh->qClass));
//		response += sizeof(QueryHeader);
//		tracker += sizeof(QueryHeader);
//
//	}
//	return tracker;
//}
//int parseAnswers(char* tracker, char* response, FixedDNSheader* fdh, int bytes) {
//	int pos = 0;
//	if (fdh->answers == 0) {
//		return 0;
//	}
//	
//	
//	printf("\t============ [answers] ============\n");
//
//	for (int i = 0; i < htons(fdh->answers); i++){
//		
//		if (tracker - response >= bytes) {
//			printf("\t ++invalid record: note enough records\n");			
//		}
//
//		int offset = calculateJump(response, tracker);
//		if (offset != 0) {	//compressed
//			char* answer = response + offset;
//			string ansString;
//			char* index = tracker;
//			while (index[0] != 0) {
//				if (index[0] == 0xFFFFFFC0) {
//					int off = calculateJump(response, index);
//					char* answer = response + off;
//					string qString;
//					while (answer[0] != 0) {
//						int size = (int)answer[0];
//						answer++;
//						char temp[256];
//						memcpy(temp, answer, size);
//						temp[size] = 0;
//						qString += temp;
//						answer += size;
//						if (answer[1] != 0) {
//							qString += ".";
//						}
//					}
//					ansString += qString;
//					index += 2;
//					if (index[0] == 0xFFFFFFC0) {
//						break;
//					}
//
//				}
//				else {
//					int size = (int)index[0];
//					index++;
//					pos++;
//					char temp[256];
//					memcpy(temp, index, size);
//					temp[size] = 0;
//					ansString += temp;
//					index += size;
//					pos += size;
//				}
//
//
//				if (index[1] != 0) {
//					ansString += ".";
//				}
//			}
//		}
//		else {	//not compressed
//			string qString;
//			char* index = tracker;
//			while (index[0] != 0) {
//				int size = (int)index[0];
//				index++;
//				pos++;
//				char temp[256];
//				memcpy(temp, index, size);
//				temp[size] = 0;
//				qString += temp;
//				index += size;
//				pos += size;
//				if (index[1] != 0) {
//					qString += ".";
//				}
//			}
//		}
//		DNSanswerHdr* answerHDR = (DNSanswerHdr*)(tracker);
//		string qType;
//		int response_type = htons(answerHDR->type);
//		switch (response_type) {
//		case 1:
//			qType = "A";
//			break;
//		case 2:
//			qType = "NS";
//			break;
//		case 5:
//			qType = "CNAME";
//			break;
//		case 12:
//			qType = "PTR";
//			break;
//		default: qType = "ERROR";
//		}
//		tracker += sizeof(DNSanswerHdr);
//		pos += sizeof(DNSanswerHdr);
//
//		char saddr[MAX_DNS_SIZE];
//
//		if (qType == "A") {
//			sprintf(saddr, "%d.%d.%d.%d", (unsigned char)tracker[0], (unsigned char)tracker[1], (unsigned char)tracker[2], (unsigned char)tracker[3]);
//			tracker += 4;
//			pos += 4;
//		}
//		else {
//			string ansString;
//			char* index = tracker;
//			while (index[0] != 0) {
//				if (index[0] == 0xFFFFFFC0) {
//					int off = calculateJump(response, index);
//					char* answer = response + off;
//					string qString;
//					while (answer[0] != 0) {
//						int size = (int)answer[0];
//						answer++;
//						char temp[256];
//						memcpy(temp, answer, size);
//						temp[size] = 0;
//						qString += temp;
//						answer += size;
//						if (answer[1] != 0) {
//							qString += ".";
//						}
//					}
//					ansString += qString;
//					index+=2;
//					if (index[0] == 0xFFFFFFC0) {
//						break;
//					}
//					
//				}
//				else {
//					int size = (int)index[0];
//					index++;
//					pos++;
//					char temp[256];
//					memcpy(temp, index, size);
//					temp[size] = 0;
//					ansString += temp;
//					index += size;
//					pos += size;
//				}
//				
//			
//				if (index[1] != 0) {
//					ansString += ".";
//				}
//			}
//			strcpy(saddr, ansString.c_str());
//			tracker = index;
//		}
//		
//		cout << qType << " " << saddr << " TTL = " << htons(answerHDR->ttl) << endl;
//		printMem(tracker);
//		
//
//
//	}
//
//	return pos;
//}

int parseAuthority(char* tracker, char* response, FixedDNSheader* fdh, int bytes) {
	int pos = 0;
	if (fdh->authority == 0) {
		return 0;
	}


	printf("\t============ [authority] ============\n");

	for (int i = 0; i < htons(fdh->answers); i++) {

		if (tracker - response >= bytes) {
			printf("\t ++invalid record: note enough records\n");
		}
		int bts = 0;

		int offset = calculateJump(response, tracker);
		if (offset != 0) {	//compressed
			char* answer = response + offset;
			string qString;
			while (answer[0] != 0) {
				int size = (int)answer[0];
				answer++;
				char temp[256];
				memcpy(temp, answer, size);
				temp[size] = 0;
				qString += temp;
				answer += size;
				if (answer[1] != 0) {
					qString += ".";
				}
			}
			tracker += 2;
			cout << "\t      " << qString << " ";
		}
		else {	//not compressed
			string qString;
			char* index = tracker;
			while (index[0] != 0) {
				int size = (int)index[0];
				printf("%d", size);
				index++;
				char temp[256];
				memcpy(temp, index, size);
				temp[size] = 0;
				qString += temp;
				index += size;
				if (index[1] != 0) {
					qString += ".";
				}
			}
			tracker += bts;
		}
		DNSanswerHdr* answerHDR = (DNSanswerHdr*)(tracker);
		string qType;
		int response_type = htons(answerHDR->type);
		switch (response_type) {
		case 1:
			qType = "A";
			break;
		case 2:
			qType = "NS"; 
				break;
		case 5:
			qType = "CNAME";
			break;
		case 12:
			qType = "PTR";
			break;
		default: qType = "ERROR";
		}
		tracker += sizeof(DNSanswerHdr);

		char saddr[16];
		sprintf(saddr, "%d.%d.%d.%d", (unsigned char)tracker[0], (unsigned char)tracker[1], (unsigned char)tracker[2], (unsigned char)tracker[3]);

		cout << qType << " " << saddr << " TTL = " << htons(answerHDR->ttl) << endl;

		tracker += 4;


	}





	return 0;
}

bool checkFDHerrors(FixedDNSheader* original, FixedDNSheader* response) {
	if (original->ID != response->ID) {
		printf("\t++ invalid reply: TXID mismatch, sent 0x.4x, received 0x.4X\n", original->ID, htons(response->ID));
		return false;
	}
	if ((htons(response->flags) & 0x000f) == 0) {
		printf("\tsucceeded with Rcode = %d\n", htons(response->flags) & 0x000f);
	}
	else {
		printf("\t failed with Rcode %d\n", htons(response->flags) & 0x000f);
		return false;
	}



	return true;
}

int main(int argc, char* argv[]){
	/*if (argc != 3) {
		cout << "Invalid input arguments\nFormat: ./hw2.exe <hostname/IP> <DNS IP>\n";
		return 0;
	}
	char* input_hostname = argv[1];
	char* dns_ip = argv[2];*/
	
	//char input_hostname[] = "www.google.com\0";
	char* input_hostname = new char[MAX_DNS_SIZE]; 
	//string host = "74.6.143.25\0";
	string host = "www.amazon.com\0";
	strcpy(input_hostname, host.c_str());

	//char* dns_ip = argv[2];
	char dns_ip[] = "8.8.8.8\0";
	int type;
	if (inet_addr(input_hostname) != INADDR_NONE) {
		type = DNS_PTR;
		string new_host = reverseLookup(input_hostname);
		strcpy(input_hostname, new_host.c_str());
	}
	else {
		type = DNS_A;
	}
	//Build DNS query packet
	int pkt_size = strlen(input_hostname) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
	char* buf = constructQuery(input_hostname, type, host);
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
			printf("\tTXID 0x%.4X flags 0x%.4X questions %d answers %d authority %d additional %d\n", htons(fdh_response->ID), htons(fdh_response->flags), (int)htons(fdh_response-> questions), (int)htons(fdh_response-> answers), (int)htons(fdh_response-> authority), (int)htons(fdh_response->additional));
			

			if (!checkFDHerrors(fdh, fdh_response)) {
				return 0;
			}
			/*int currPos = parseQuestions(tracker, input_hostname, fdh);
			tracker += currPos;*/
			tracker = parseQuestions(response_buf, tracker, fdh_response);
			//tracker += pkt_size - sizeof(FixedDNSheader)+1;
			for (int i = 0; i < 24; i++) {
				printf("tracker[%d] = %.2X\n", i, tracker[i]);
			}
			/*currPos = parseAnswers(tracker, response_buf, fdh_response, bytes);
			tracker += currPos;
			printf("tracker = %X\n", tracker);

			currPos = parseAuthority(tracker, response_buf, fdh_response, bytes);*/

			//currPos = parseAnswers(response, currPos);
				// parse questions and arrive to the answer section
				
				// suppose off is the current position in the packet
				//FixedRR * frr = (FixedRR*)(buf + off);
			// read frr->len and other fields
			

			break;
		}
		// error checking here
		cout << " timeout in 10000 ms" << endl;
	}
	WSACleanup();
	delete buf;
	

	return 0;
}

