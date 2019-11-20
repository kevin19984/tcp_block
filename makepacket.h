#pragma once
#pragma pack(1)

struct temheader{
	uint32_t srcIP;
	uint32_t destIP;
	uint8_t reserved=0;
	uint8_t protocol=6;
	uint16_t tcplen;
};

uint16_t ipchksum(iphdr* ipheader, int iplen);
uint16_t tcpchksum(iphdr* ipheader, tcphdr* tcpheader, u_char* tempkt, int iplen, int tempktlen);
void forwRSTpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen);
void forwFINpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen);
void backwRSTpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen);
void backwFINpkt(const u_char* packet, u_char* mpacket, char* host, int headerlen, uint32_t datalen);

