#include <stdint.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "makepacket.h"

uint16_t ipchksum(iphdr* ipheader, int iplen)
{
	ipheader -> check = htons(0);
	int sum = 0;
	int tem;
	u_char* iptem = (u_char*)ipheader;
	for(int i=0; i<iplen; i+=2)
	{
		tem = (iptem[i] << 8) + iptem[i+1];
		sum += tem;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum ^= 0xFFFF;
	return (uint16_t)sum;
}

uint16_t tcpchksum(iphdr* ipheader, tcphdr* tcpheader, u_char* tempkt, int iplen, int tempktlen)
{
	temheader tem;
	tem.srcIP = ipheader -> saddr;
	tem.destIP = ipheader -> daddr;
	tem.tcplen = htons(ntohs(ipheader -> tot_len) - iplen);
	int temlen = 12;
	int tem2;		
	int sum1 = 0;
	u_char* temtem = (u_char*)&tem;
	for(int i=0; i<temlen; i+=2)
	{
		tem2 = (temtem[i] << 8) + temtem[i+1];
		sum1 += tem2;
	}
	sum1 = (sum1 >> 16) + (sum1 & 0xFFFF);
	sum1 = (sum1 >> 16) + (sum1 & 0xFFFF);
	tcpheader -> th_sum = htons(0);
	int sum2 = 0;
	int flag = 0;
	for(int i=0; i<tempktlen; i+=2)
	{
		if(i == tempktlen - 1)
			tem2 = (tempkt[i] << 8);
		else
			tem2 = (tempkt[i] << 8) + tempkt[i+1];
		sum2 += tem2;
	}
	sum2 = (sum2 >> 16) + (sum2 & 0xFFFF);
	sum2 = (sum2 >> 16) + (sum2 & 0xFFFF);
	int sum3 = sum1 + sum2;
	sum3 = (sum3 >> 16) + (sum3 & 0xFFFF);
	sum3 = (sum3 >> 16) + (sum3 & 0xFFFF);
	sum3 ^= 0xFFFF;
	return (uint16_t)sum3;
}

void forwRSTpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen)
{
	memcpy(mpacket, packet, headerlen);
	iphdr* temip = (iphdr*)(packet + ETH_HLEN);
	int iplen = (temip -> ihl) * 4;
	iphdr* temip2 = (iphdr*)(mpacket + ETH_HLEN);
	temip2 -> tot_len = htons(headerlen - ETH_HLEN);
	uint16_t ipchk = ipchksum(temip2, (temip2 -> ihl) * 4);
	temip2 -> check = htons(ipchk);
	tcphdr* temtcp = (tcphdr*)(mpacket + ETH_HLEN + iplen);
	temtcp -> th_seq = htonl(ntohl(temtcp -> th_seq) + datalen);
	temtcp -> th_flags &= 0x00;
	temtcp -> th_flags |= 0x04;
	u_char* tempkt = (u_char*)(mpacket + ETH_HLEN + iplen);
	uint16_t tcpchk = tcpchksum(temip2, temtcp, tempkt, iplen, headerlen - ETH_HLEN - iplen);
	temtcp -> th_sum = htons(tcpchk);
}

void forwFINpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen)
{
	memcpy(mpacket, packet, headerlen);
	iphdr* temip = (iphdr*)(packet + ETH_HLEN);
	int iplen = (temip -> ihl) * 4;
	iphdr* temip2 = (iphdr*)(mpacket + ETH_HLEN);
	temip2 -> tot_len = htons(headerlen - ETH_HLEN);
	uint16_t ipchk = ipchksum(temip2, (temip2 -> ihl) * 4);
	temip2 -> check = htons(ipchk);
	tcphdr* temtcp = (tcphdr*)(mpacket + ETH_HLEN + iplen);
	temtcp -> th_seq = htonl(ntohl(temtcp -> th_seq) + datalen);
	temtcp -> th_flags &= 0x00;
	temtcp -> th_flags |= 0x19;
	u_char* tempkt = (u_char*)(mpacket + ETH_HLEN + iplen);
	uint16_t tcpchk = tcpchksum(temip2, temtcp, tempkt, iplen, headerlen - ETH_HLEN - iplen);
	temtcp -> th_sum = htons(tcpchk);
}

void backwRSTpkt(const u_char* packet, u_char* mpacket, int headerlen, uint32_t datalen)
{
	memcpy(mpacket, packet, headerlen);
	ether_header* etherheader = (ether_header*)packet;
	ether_header* etherheader2 = (ether_header*)mpacket;
	memcpy(etherheader2 -> ether_dhost, etherheader -> ether_shost, ETH_ALEN);
	memcpy(etherheader2 -> ether_shost, etherheader -> ether_dhost, ETH_ALEN);
	iphdr* temip = (iphdr*)(packet + ETH_HLEN);
	iphdr* temip2 = (iphdr*)(mpacket + ETH_HLEN);
	int iplen = (temip -> ihl) * 4;
	temip2 -> saddr = temip -> daddr;
	temip2 -> daddr = temip -> saddr;
	temip2 -> tot_len = htons(headerlen - ETH_HLEN);
	uint16_t chksum = ipchksum(temip2, iplen);
	temip2 -> check = htons(chksum);
	tcphdr* temtcp = (tcphdr*)(packet + ETH_HLEN + iplen);
	tcphdr* temtcp2 = (tcphdr*)(mpacket + ETH_HLEN + iplen);
	temtcp2 -> th_sport = temtcp -> th_dport;
	temtcp2 -> th_dport = temtcp -> th_sport;
	temtcp2 -> th_seq = temtcp -> th_ack;
	temtcp2 -> th_ack = htonl(ntohl(temtcp -> th_seq) + datalen);
	temtcp2 -> th_flags &= 0x00;
	temtcp2 -> th_flags |= 0x04; 
	u_char* tempkt = (u_char*)(mpacket + ETH_HLEN + iplen);
	uint16_t tcpchk = tcpchksum(temip2, temtcp2, tempkt, iplen, headerlen - ETH_HLEN - iplen);
	temtcp2 -> th_sum = htons(tcpchk);
}

void backwFINpkt(const u_char* packet, u_char* mpacket, char* host, int headerlen, uint32_t datalen)
{
	memcpy(mpacket, packet, headerlen);
	ether_header* etherheader = (ether_header*)packet;
	ether_header* etherheader2 = (ether_header*)mpacket;
	memcpy(etherheader2 -> ether_dhost, etherheader -> ether_shost, ETH_ALEN);
	memcpy(etherheader2 -> ether_shost, etherheader -> ether_dhost, ETH_ALEN);
	iphdr* temip = (iphdr*)(packet + ETH_HLEN);
	iphdr* temip2 = (iphdr*)(mpacket + ETH_HLEN);
	int iplen = (temip -> ihl) * 4;
	temip2 -> saddr = temip -> daddr;
	temip2 -> daddr = temip -> saddr;
	int hostlen = strlen(host);
	temip2 -> tot_len = htons(headerlen - ETH_HLEN + hostlen + 272);
	temip2 -> frag_off = htons(0x0000);
	temip2 -> ttl = 0x80;
	uint16_t chksum = ipchksum(temip2, iplen);
	temip2 -> check = htons(chksum);
	tcphdr* temtcp = (tcphdr*)(packet + ETH_HLEN + iplen);
	tcphdr* temtcp2 = (tcphdr*)(mpacket + ETH_HLEN + iplen);
	temtcp2 -> th_sport = temtcp -> th_dport;
	temtcp2 -> th_dport = temtcp -> th_sport;
	temtcp2 -> th_seq = temtcp -> th_ack;
	temtcp2 -> th_ack = htonl(ntohl(temtcp -> th_seq) + datalen);
	temtcp2 -> th_flags &= 0x00;
	temtcp2 -> th_flags |= 0x19; 
	temtcp2 -> th_win = htons(0xffff);
	int filedatalen = 207 + hostlen;
	u_char tem1[80] = {0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x32, 0x31, 0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x0d, 0x0a};
	tem1[33] = (filedatalen / 100) + 48;
	filedatalen -= (filedatalen / 100) * 100;
	tem1[34] = (filedatalen / 10) + 48;
	filedatalen -= (filedatalen / 10) * 10;
	tem1[35]= filedatalen + 48;
	u_char tem2[200] = "<html><head><meta http-equiv=\"pragma\" content=\"no-cache\"><meta http-equiv=\"refresh\" content=\"0;url=\'http://www.warning.or.kr/i1.html?flag=D&uid=?&gid=10&did=3f&pid=0&cid=1&host=";
	u_char tem3[40] = "&uri=2f&mwn=?\'\"></head></html>";
	for(int i=0; i<65; i++)
		mpacket[headerlen + i] = tem1[i];
	for(int i=0; i<177; i++)
		mpacket[headerlen + 65 + i] = tem2[i];
	for(int i=0; i<hostlen; i++)
		mpacket[headerlen + 242 + i] = host[i];
	for(int i=0; i<30; i++)
		mpacket[headerlen + hostlen + 242 + i] = tem3[i];
	u_char* tempkt = (u_char*)(mpacket + ETH_HLEN + iplen);
	uint16_t tcpchk = tcpchksum(temip2, temtcp2, tempkt, iplen, headerlen - ETH_HLEN - iplen + hostlen + 272);
	temtcp2 -> th_sum = htons(tcpchk);
}

