#include "pcap.h"
#include <iostream>
#include <vector>
#include<string>
#include<Winsock2.h>

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];	// 目的地址
	BYTE 	SrcMAC[6];	// 源地址
	WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;
	BYTE	TOS;
	WORD	TotalLen;
	WORD	ID;
	WORD	Flag_Segment;
	BYTE	TTL;
	BYTE	Protocol;
	WORD	Checksum;
	ULONG	SrcIP;
	ULONG	DstIP;
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式

struct dev
{
	char* name;
	std::string descrip;
	std::string addr;
	std::string netmask;
	
};
std::vector<dev> devices;


void getAllDev()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE]; // 宏定义给定长度
	struct in_addr net_mask_address;
	struct in_addr net_ip_address;

	uint32_t net_ip;
	uint32_t net_mask;

	// 获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // Interface  
		NULL,	// 无需认证
		&alldevs,	// 列表首部
		errbuf
	) == -1)
	{
		std::cout << "ERROR";
		pcap_freealldevs(alldevs);
		return;
	}
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev temp;
		temp.name = d->name;
		temp.descrip = d->description;
		pcap_lookupnet(d->name, &net_ip, &net_mask, errbuf); // 获取掩码以及IP地址
		net_ip_address.s_addr = net_ip;
		net_mask_address.s_addr = net_mask;
		
		for (a = d->addresses; a != NULL; a = a->next) {	
			if (a->addr->sa_family == AF_INET)  // 判读地址是否为IP地址
			{
				
				temp.addr = inet_ntoa(net_ip_address);
				temp.netmask = inet_ntoa(net_mask_address);
				
				//temp.addr = inet_ntoa(((struct sockaddr_in*)&(a->addr))->sin_addr); // 这样获取IP地址为何不对？
				devices.push_back(temp);
				
				
			}
		}
	}
	pcap_freealldevs(alldevs);
}

void output()
{
	for (std::vector<dev>::iterator it = devices.begin(); it != devices.end(); it++)
	{
		std::cout << it->name << std::endl
			<< "description:" << it->descrip << std::endl
			<< "IPaddr:" << it->addr << std::endl
			<< "netmask:" << it->netmask << std::endl;
		//	<< "broadaddr:" << it->broadaddr << std::endl
		//<< "dstaddr:" << it->dstaddr << std::endl;
		std::cout << std::endl;
	}
	std::cout <<"The numbers of NIC: " << devices.size()<<std::endl;
}

void capturePacket()
{
	char errbuf[PCAP_ERRBUF_SIZE]; // 宏定义给定长度
	int nicId;
	int res;
	pcap_t* adapter; // pcap_open返回值
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	Data_t* IPPacket;
	ULONG		SourceIP, DestinationIP;

	if (devices.empty())
	{
		std::cout << "Can not find devices!"<<std::endl;
		return;
	}
	output();
	std::cout << "Please choose the NIC:" << std::endl;
	std::cin >> nicId;
	if (nicId >= devices.size() || nicId < 0) 
	{
		std::cout << "NIC not exsits.Choose again!" << std::endl;
		return;
	}
	if ((adapter = pcap_open(devices[nicId].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, errbuf)) == NULL) //snaplen表示包的长度
	{
		std::cout << "Open failed!";
		return;
	}
	else
	{
		std::cout << "Monitor NIC:" << std::endl << devices[nicId].name<<std::endl<<devices[nicId].descrip<<std::endl;
	}
	if ((res = pcap_next_ex(adapter, &pkt_header, &pkt_data)) != 1) // 不是所有端口都在使用，2、3可以
	{
		if (res != 0)
			std::cout << "Cpature fialed，try another NIC! Error code: " << res << std::endl;
		else
			std::cout << "Out of time, try again!";
		return;
	}

	IPPacket = (Data_t*)pkt_data;
	SourceIP = ntohl(IPPacket->IPHeader.SrcIP);
	DestinationIP = ntohl(IPPacket->IPHeader.DstIP);
	std::cout << "Sip" << SourceIP;

}


int main()
{


	getAllDev();
	//output();
	capturePacket();
}
