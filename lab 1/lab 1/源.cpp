#include "pcap.h"
#include <iostream>
#include <vector>
#include <string>
struct dev 
{
	std::string name;
	std::string descrip;
	sockaddr* addr;
	sockaddr* netmask;
	sockaddr* broadaddr;
	sockaddr* dstaddr;
};
std::vector<dev> devices;
void clear()
{
	devices.clear();
}
void getAllDev()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];

	// ��ȡ�������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // Interface  
		NULL,	// ������֤
		&alldevs,	// �б��ײ�
		errbuf
	) == -1)
	{
		std::cout<<"ERROR";
		return;
	}
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev temp;
		temp.name = d->name;
		temp.descrip = d->description;
		for(a = d->addresses;a!=NULL;a = a->next)
			if (a->addr->sa_family == AF_INET)  // �ж���ַ�Ƿ�ΪIP��ַ
			{
				temp.addr = a->addr;
				temp.netmask = a->netmask;
				temp.broadaddr = a->broadaddr;
				temp.dstaddr = a->dstaddr;
			}
		devices.push_back(temp);
	}
	pcap_freealldevs(alldevs);
}

int main()
{
	clear();
	getAllDev();
	for (std::vector<dev>::iterator it = devices.begin(); it != devices.end(); it++)
	{
		std::cout << it->name<<std::endl;
	}
}
