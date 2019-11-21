#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include "boyer_moore.h"
#include "makepacket.h"
using namespace std;

int jump[300];
unsigned char pattern[9] = {0x0d, 0x0a, 'H', 'o', 's', 't', ':', ' ', '\0'};
int patternlen = 8;
unsigned char mpacket[66000];

void usage() {
	printf("syntax: tcp_block <interface> <host>\n");
	printf("sample: tcp_block wlan0 test.gilgil.net\n");
}

void dump(const unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

int chkpacket(const u_char* packet, char* host)
{
	ether_header* etherheader = (ether_header*)packet;
	if (ntohs(etherheader -> ether_type) != ETHERTYPE_IP)
		return 0;
	iphdr* ipheader = (iphdr*)(packet + ETH_HLEN);
	int iplen = (ipheader -> ihl) * 4;
	if (ipheader -> protocol != 6)
		return 0;
	tcphdr* tcpheader = (tcphdr*)(packet + ETH_HLEN + iplen);
	int tcplen = (tcpheader -> th_off) * 4;
	int iptotlen = ntohs(ipheader -> tot_len); 
	int tcpdatalen = iptotlen - iplen - tcplen;
	if (tcpdatalen <= 0)
		return 0;
	unsigned char* tcpdata = (unsigned char*)(packet + ETH_HLEN + iplen + tcplen);
	if(memcmp(tcpdata, "GET", 3) == 0 || memcmp(tcpdata, "POST", 4) == 0 || memcmp(tcpdata, "HEAD", 4) == 0 || memcmp(tcpdata, "PUT", 3) == 0 || memcmp(tcpdata, "DELETE", 6) == 0 || memcmp(tcpdata, "OPTIONS", 7) == 0)
	{
		int hostlen = strlen(host);
		int datahostlen = 0;
		int pos = BoyerMooreHorspool(tcpdata, tcpdatalen, pattern, patternlen, jump);
		if(pos == -1)
			return 0;
		for(int i=pos+8; i<tcpdatalen; i++)
		{
			if(tcpdata[i] == 0x0d && tcpdata[i+1] == 0x0a)
			{
				datahostlen = i - (pos + 8);
				break;
			}
		}
		if(memcmp(host, tcpdata + pos + 8, min(hostlen, datahostlen)) == 0)
			return ETH_HLEN + iplen + tcplen;
	}
	return 0;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* host = argv[2];
	int hostlen = strlen(host);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	computeJump(pattern, patternlen, jump);
	printf("Start blocking\n");	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
    
		int headerlen = chkpacket(packet, host);
		if(headerlen == 0) continue;
		uint32_t datalen = header -> caplen - headerlen;
		//dump(packet, headerlen);
		
		forwRSTpkt(packet, mpacket, headerlen, datalen);
		if(pcap_sendpacket(handle, mpacket, headerlen) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			return -1;
		}
		
		
		backwRSTpkt(packet, mpacket, headerlen, datalen);
		if(pcap_sendpacket(handle, mpacket, headerlen) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			return -1;
		}
		
		/*
		forwFINpkt(packet, mpacket, headerlen, datalen);
		if(pcap_sendpacket(handle, mpacket, headerlen) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			return -1;
		}
		*/
		/*
		backwFINpkt(packet, mpacket, host, headerlen, datalen);
		if(pcap_sendpacket(handle, mpacket, headerlen + hostlen + 272) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			return -1;
		}
		*/
	}
	pcap_close(handle);
	return 0;
}
