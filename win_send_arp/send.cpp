#define WIN32
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib") // mac
#include "pcap.h"
#include <stdio.h>
#include <string.h>
#include <winsock.h>
#include <windows.h>
#include <stdlib.h>
#include <IPHlpApi.h>

// 기초 세팅
// 프로젝트 속성 -> VC++ 디렉토리
// 포함 디렉토리 : WpdPac\include
// 라이브러리 디렉토리 : WpdPac\Lib

char* getMAC(const char *ip) {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char *mac_addr = (char*)malloc(17);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return NULL;
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		do {
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("Address: %s, mac: %s", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			if (strcmp(ip, pAdapterInfo->IpAddressList.IpAddress.String) == 0) {
				printf(" matches\n");
				free(AdapterInfo);
				return mac_addr;
			}
			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	return NULL;
}


struct arp_packet {
	char  eth_dst_addr[6];
	char  eth_src_addr[6];
	short eth_frame_type;
	short htype;
	short ptype;
	char  hlen;
	char  plen;
	short oper;
	char  sha[6];
	char  spa[4];
	char  tha[6];
	char  tpa[4];
	char  trail[18];
};

static char errbuf[PCAP_ERRBUF_SIZE];

void print_list()
{
	pcap_if_t *devs;
	if (-1 == pcap_findalldevs(&devs, errbuf))
	{
		printf("Couldn't open device list: %s\n", errbuf);
		return;
	}
	if (!devs) {
		printf("No devices found.");
		return;
	}
	for (pcap_if_t *d = devs; d; d = d->next) {
		printf("%s (%s)\n", d->name, d->description);
	}
	pcap_freealldevs(devs);
}
void set_mac(char* str, char* dstx)
{
	short* dst = (short*)dstx;
	for (int i = 0; i < 3; i++)
	{
		sscanf(str + i * 4, "%4hx", dst + i);
		dst[i] = htons(dst[i]);
	}
}
void send_packet(char *dev, char *srcmac, char *dstmac, char* sendmac, char* targetmac, char *sendip, char* targetip)
{
	struct arp_packet p = { 0 };

	set_mac(dstmac, p.eth_dst_addr);
	set_mac(srcmac, p.eth_src_addr);
	p.eth_frame_type = htons(0x0806);
	p.htype = htons(0x0001);
	p.ptype = htons(0x0800);
	p.hlen = 6;
	p.plen = 4;
	p.oper = htons(0x0002);
	set_mac(sendmac, p.sha);
	set_mac(targetmac, p.tha);
	*(u_long*)p.spa = inet_addr(sendip);
	*(u_long*)p.tpa = inet_addr(targetip);

	pcap_t *pc;
	dev = pcap_lookupdev(errbuf);
	if (!(pc = pcap_open_live(dev, 65535, 1, 1, errbuf)))
	{
		printf("Couldn't open device %s: %s", dev, errbuf);
		return;
	}
	if (0 != pcap_sendpacket(pc, ((u_char*)&p), sizeof(arp_packet)))
	{
		printf("Error sending packet: %s", pcap_geterr(pc));
		return;
	}
	else
	{
		printf("ARP packet sent.");
	}
	pcap_close(pc);
}

int main(int argc, char* argv[])
{
	print_list();
	char mac[6] = { 0xFF, };
	send_packet("Intel(R) Ethernet Connection (2) I219-V", "192.168.0.4", "192.168.0.3", getMAC("192.168.0.4"), mac, "192.168.0.4", "192.168.0.3");
	return 0;
}