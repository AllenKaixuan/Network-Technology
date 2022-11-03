#include "pcap.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include<string>
#include<Winsock2.h>

#define SENDDEVICE "Network adapter 'MediaTek Wi-Fi 6 MT7921 Wireless LAN Card' on local host"
#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t {	//֡�ײ�
	BYTE	DesMAC[6];	// Ŀ�ĵ�ַ
	BYTE 	SrcMAC[6];	// Դ��ַ
	WORD	FrameType;	// ֡����
} FrameHeader_t;


typedef struct ARPFrame_t {
	FrameHeader_t Frameheader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;
#pragma pack()	//�ָ�ȱʡ���뷽ʽ

struct dev
{
	char* name;
	std::string descrip;
	std::string addr;
	std::string netmask;
	std::string broadaddr;

};
std::vector<dev> devices;
const u_char* pkt_data;
std::string hostMac;
ARPFrame_t* ARPProtocal;

uint32_t netMask; // ѡ���豸����������
time_t start, now;//��ʱ
long float time_sum;
int nicId;


int nicFind();  // ���豸�б���ɸѡ����������


void getAllDev()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE]; // �궨���������
	struct in_addr net_mask_address;
	struct in_addr net_ip_address;

	uint32_t net_ip;
	uint32_t net_mask;

	// ��ȡ�������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // Interface  
		NULL,	// ������֤
		&alldevs,	// �б��ײ�
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
		pcap_lookupnet(d->name, &net_ip, &net_mask, errbuf); // ��ȡ�����Լ�IP��ַ
		net_ip_address.s_addr = net_ip;
		net_mask_address.s_addr = net_mask;

		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET)  // �ж���ַ�Ƿ�ΪIP��ַ
			{

				temp.addr = inet_ntoa(net_ip_address);
				temp.netmask = inet_ntoa(net_mask_address);

				//temp.addr = inet_ntoa(((struct sockaddr_in*)&(a->addr))->sin_addr); // ������ȡIP��ַΪ�β��ԣ�
				if (temp.descrip == SENDDEVICE)
					netMask = net_mask;  // �����Ҫ�豸������

				devices.push_back(temp);


			}
		}
	}

	pcap_freealldevs(alldevs);
	nicId = nicFind();
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
	std::cout << "The numbers of NIC: " << devices.size() << std::endl;
}

void output(int id)
{
	std::cout << devices[id].name << std::endl
		<< "description:" << devices[id].descrip << std::endl
		<< "IPaddr:" << devices[id].addr << std::endl
		<< "netmask:" << devices[id].netmask << std::endl;
	std::cout << std::endl;
}


std::string transIp(DWORD in)//��Ӧ��IP��ַ
{
	std::string ans;
	DWORD mask[] = { 0xFF000000,0x00FF0000,0x0000FF00,0x000000FF };
	DWORD num[4];

	num[0] = in & mask[0];
	num[0] = num[0] >> 24;
	num[1] = in & mask[1];
	num[1] = num[1] >> 16;
	num[2] = in & mask[2];
	num[2] = num[2] >> 8;
	num[3] = in & mask[3];

	char temp[100];
	sprintf_s(temp, "%d.%d.%d.%d", num[0], num[1], num[2], num[3]);
	ans = temp;
	return ans;
}
u_long ipTrans(std::string in)
{
	char ipaddr[100];
	strcpy(ipaddr, in.c_str());
	DWORD num[4];
	sscanf_s(ipaddr, "%u.%u.%u.%u", &num[0], &num[1], &num[2], &num[3]);
	num[0] = num[0] << 24;
	num[1] = num[1] << 16;
	num[2] = num[2] << 8;
	u_long temp = num[0] + num[1] + num[2] + num[3];
	return htonl(temp);
	
}
std::string transMac(BYTE* MAC)//Ŀ�ĵ�ַ��Դ��ַ
{
	std::string ans;
	char temp[100];
	sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
	ans = temp;
	return ans;
}

BYTE* macTrans(std::string in)
{
	char temp[100];
	strcpy(temp, in.c_str());
	unsigned char* MAC = new unsigned char[6];
	sscanf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
	return MAC;

}

int nicFind()  // ���豸�б���ɸѡ����������
{
	for (int i = 0; i < devices.size(); i++)
	{
		if (devices[i].descrip == SENDDEVICE)
			return i;
	}
}

void capturePacket()
{
	char errbuf[PCAP_ERRBUF_SIZE]; // �궨���������
	
	int res;
	pcap_t* adapter; // pcap_open����ֵ
	pcap_pkthdr* pkt_header;
	struct bpf_program fcode; //�洢һ������õĹ�����
	
	ULONG		SourceIP, DestinationIP;

	if (devices.empty())
	{
		std::cout << "Can not find devices!" << std::endl;
		return;
	}
	output(nicId);

	if ((adapter = pcap_open(devices[nicId].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, errbuf)) == NULL) //snaplen��ʾ���ĳ���
	{
		std::cout << "Open failed!" << std::endl;
		return;
	}

	if (pcap_compile(adapter, &fcode, "arp", 1, netMask) < 0)  // ���������
	{
		std::cout << "Compile failed!" << std::endl;
		return;
	}

	if (pcap_setfilter(adapter, &fcode) < 0)
	{
		std::cout << "Set filter failed!" << std::endl;
		return;
	}

	start = time(NULL);
	while ((res = pcap_next_ex(adapter, &pkt_header, &pkt_data)) >= 0)
	{
		now = time(NULL);
		if (res == 0) 
		{
			printf("Waiting:%f seconds\n", time_sum);
			continue;
		}
		if ((time_sum = difftime(now, start)) > 15) // ��ʱ
			break;
		ARPProtocal = (ARPFrame_t*)(pkt_data);
		if (ARPProtocal->Frameheader.FrameType== htons(0x0806))
		{
			
			if (ARPProtocal->Operation == htons(0x0002))
			{
				std::cout << "SrcMAC: " << transMac(ARPProtocal->SendHa) << std::endl;
				std::cout << "DstMAC: " << transMac(ARPProtocal->RecvHa) << std::endl;
				if (ARPProtocal->SendIP == ipTrans(devices[nicId].addr))
					hostMac = transMac(ARPProtocal->SendHa);
			}
			else if (ARPProtocal->Operation == htons(0x0001))
			{
				std::cout << "requestSrcMAC: " << transMac(ARPProtocal->SendHa) << std::endl;
				std::cout << "requestDstMAC: " << transMac(ARPProtocal->RecvHa) << std::endl;
			}
			
			continue;
		}



	}


}



void sendARP(std::string destIp,std::string srcIp,std::string srcMac)
{
	char errbuf[PCAP_ERRBUF_SIZE]; // �궨���������
	int nicId = 2; // ѡ����������ץ����ȡ��Ӧ��Ϣ
	pcap_t* adapter; // pcap_open����ֵ
	ARPFrame_t ARPFrame;
	/*capturePacket();
	IPPacket = (Data_t*)pkt_data;*/
	memcpy(ARPFrame.Frameheader.SrcMAC, macTrans(srcMac),6);
	// ����Ϊ�㲥��ַ
	memset(ARPFrame.Frameheader.DesMAC, 0xff, 6);
	ARPFrame.Frameheader.FrameType = htons(0x0806);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	// ��ʹ�������ַ���򱾻�����ARP����ȡ����MAC��IP
	memcpy(ARPFrame.SendHa, macTrans(srcMac), 6); //����Ϊ����MAC
	ARPFrame.SendIP = ipTrans(srcIp); 
	memset(ARPFrame.RecvHa, 0, 6);
	ARPFrame.RecvIP = ipTrans(destIp);
	if ((adapter = pcap_open(devices[nicId].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 6000, NULL, errbuf)) == NULL) //snaplen��ʾ���ĳ���
	{
		std::cout << "Open failed!" << std::endl;
	}
	if (pcap_sendpacket(adapter, (const u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		std::cout << "Send failed!" << std::endl;
	else
	{
		std::cout << "Send successful!" << std::endl;
		return;
	}

}

int main()
{


	getAllDev();
	//output();
	
	
	std::string dstIp,srcIp,srcMac;
	
	sendARP(devices[nicId].addr,"112.112.112.112","66-66-66-66-66-66"); // �����������ַ�򱾻�IP�������ݰ�����ȡ����MAC
	
	//sendARP("192.168.192.126", devices[nicId].addr, hostMac);
	capturePacket();

}
