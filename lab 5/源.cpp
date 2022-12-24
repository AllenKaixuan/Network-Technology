#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Protocol.h"
#pragma comment(lib,"ws2_32.lib")//����ws2_32.lib���ļ�������Ŀ��
#include <stdio.h>
#include <time.h>
//�궨��
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10
#define DEFAULT 0  // Ĭ��·��
#define USER 1   // �û����

bpf_u_int32 netmask_g = 0x00ffffff;
int WaitPkt;
log ltable;
HANDLE hThread;
DWORD dwThreadId;


int index;
int main()
{

	//const char* ��char*��ת��
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);

	find_alldevs();//��ȡ����ip

	for (int i = 0; i < 2; i++)//�����ʱ�洢��IP��ַ����������
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	getselfmac(inet_addr(ip[0]));
	getmac(selfmac);
	BYTE mac[6];
	int opcode;
	routetable rtable;
	hThread = CreateThread(NULL, NULL, handle, LPVOID(&rtable), 0, &dwThreadId);
	routeitem a;
	while (1)
	{
		printf("add(1)��delete(2)��print(3): ");
		scanf("%d", &opcode);
		if (opcode == 1)
		{
			routeitem a;
			char t[30];
			printf("MASK��");
			scanf("%s", &t);
			a.mask = inet_addr(t);
			printf("DstIP��");
			scanf("%s", &t);
			a.net = inet_addr(t);
			printf("NextHop��");
			scanf("%s", &t);
			a.nextip = inet_addr(t);
			a.type = USER;
			rtable.add(&a);
		}
		else if (opcode == 2)
		{
			printf("Choose the index to delete��");
			int index;
			scanf("%d", &index);
			rtable.remove(index);
		}
		else if (opcode == 3)
		{
			rtable.print();
		}
		else {
			printf("Choose again!\n");
		}
	}
	routetable table;
	table.print();
	return 0;
}
//��������


//��ȡ��Ӧ������������IP��ַ
void find_alldevs()	//��ȡ�����ϵ�IP
{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1)
	{
		printf("%s", "error");
	}
	else
	{
		int num = 0;
		dev = alldevs;
		for (; dev != NULL; dev = dev->next)//��ȡ������ӿ��豸��ip��ַ��Ϣ
		{


			net[num] = dev;  // ������
			int index = 0;
			for (a = dev->addresses; a != nullptr; a = a->next)
			{
				if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
				{
					printf("No.%d ", num);
					printf("%s\t", dev->name, dev->description);
					printf("%s\t%s\n", "IPaddr:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//�洢��ӦIP��ַ��MAC��ַ
					strcpy(ip[index], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					strcpy(mask[index++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					
				}
			}
			Nic = open(dev->name);//�򿪸�����
			num++;

		}
	}
	pcap_freealldevs(alldevs);
}

pcap_t* open(char* name)//������ӿ�
{
	pcap_t* temp = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (temp == NULL)
		printf("error");
	return temp;
}

int compare(BYTE a[6], BYTE b[6])//ʶ��Ƚ�IP��ַ��MAC��ַ�����˱���
{
	int index = 1;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			index = 0;
	}
	return index;
}

void getselfmac(DWORD ip)//��ñ���IP��ַ�Լ���Ӧ��MAC��ַ
{
	memset(selfmac, 0, sizeof(selfmac));
	ARPFrame_t ARPFrame;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ

	ARPFrame.FrameHeader.SrcMAC[0] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[1] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[2] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[3] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[4] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[5] = 0x0f;

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	ARPFrame.SendHa[0] = 0x0f;
	ARPFrame.SendHa[1] = 0x0f;
	ARPFrame.SendHa[2] = 0x0f;
	ARPFrame.SendHa[3] = 0x0f;
	ARPFrame.SendHa[4] = 0x0f;
	ARPFrame.SendHa[5] = 0x0f;
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;

	ARPFrame.RecvIP = ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);


	if (Nic == nullptr) printf("Nic open failed!\n");
	else
	{
		if (pcap_sendpacket(Nic, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//���ʹ�����
			printf("senderror\n");
		}
		else
		{
			//���ͳɹ�
			while (1)
			{
				//printf("send\n");
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(Nic, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
					{//���Ŀ��MAC��ַ
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC))
						{
							ltable.log_arp(IPPacket);
							//���ԴMAC��ַ��ԴMAC��ַ��Ϊ����MAC��ַ
							for (int i = 0; i < 6; i++)
								selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;//�Ѿ�������MAC��ַ������˳�
						}
					}
				}
			}
		}
	}
}

void getothermac(DWORD table_ip, BYTE mac[])//��ȡĿ��ip��Ӧ��mac
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];

	}

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//ipprint(ARPFrame.SendIP);
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ

	ARPFrame.RecvIP = table_ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);

	if (Nic == nullptr) printf("NIC open failed!\n");
	else
	{
		if (pcap_sendpacket(Nic, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//���ʹ�����
			printf("senderror\n");
		}
		else
		{
			//���ͳɹ�
			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				struct pcap_pkthdr* header;
				
				struct bpf_program fcode;
				//compile the filter
				if (pcap_compile(Nic, &fcode, "arp", 1, netmask_g) < 0)
				{
					fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
					return;
				}

				//set the filter
				if (pcap_setfilter(Nic, &fcode) < 0)
				{
					fprintf(stderr, "\nError setting the filter.\n");
					return;
				}
				int rtn = pcap_next_ex(Nic, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
					{//���Ŀ��MAC��ַ
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == table_ip)//&&ip==IPPacket->SendIP
						{

							ltable.log_arp(IPPacket);
							//���ԴMAC��ַ
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

void getmac(BYTE MAC[])//��ӡmac
{
	printf("MAC�� ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

void routetable::add(routeitem* a)
{
	routeitem* pointer;

	//Ĭ��·��
	if (a->type == DEFAULT)//ֱ��Ͷ��
	{
		a->nextitem = head->nextitem;
		head->nextitem = a;
	}
	//���������������ɳ������ҵ����ʵ�λ��
	else
	{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
		{
			if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				break;
		}
		a->nextitem = pointer->nextitem;
		pointer->nextitem = a;//���뵽����λ��

	}
	routeitem* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++)
	{
		p->index = i;
	}
	num++;
}

void routeitem::printitem()//��ӡ·�ɱ�
{

	//index mask net nextip
	in_addr addr;
	printf("%d   ", index);
	addr.s_addr = mask;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = net;
	pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = nextip;
	pchar = inet_ntoa(addr);
	printf("%s\t\t", pchar);

	printf("%d\n", type);
}

void routetable::print()//��ӡ·�ɱ�
{
	routeitem* p = head->nextitem;
	for (; p != tail; p = p->nextitem)
	{
		p->printitem();
	}
}

routetable::routetable()//��ʼ�������ֱ�����ӵ�����
{
	head = new routeitem;
	tail = new routeitem;
	head->nextitem = tail;
	num = 0;
	for (int i = 0; i < 2; i++)
	{
		routeitem* temp = new routeitem;
		//����������ip ��������а�λ�뼴Ϊ��������
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = DEFAULT;//0��ʾֱ��Ͷ�ݵ����磬����ɾ��
		this->add(temp);//��ӱ���
	}
}

void routetable::remove(int index)//ɾ��·�ɱ���
{

	for (routeitem* t = head; t->nextitem != tail; t = t->nextitem)
	{
		if (t->nextitem->index == index)
		{
			if (t->nextitem->type == DEFAULT)//ֱ��Ͷ�ݵ�·�ɱ����ɾ��
			{
				printf("Can't remove default routeitem!\n");
				return;
			}
			else
			{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("Doesn't exist!\n");
}




//���ݱ�ת��,�޸�Դmac��Ŀ��mac
void resend(ICMP_t data, BYTE dmac[])
{
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ ����MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);//Ŀ��MACΪ��һ��MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)
		return;//����
	setchecksum(temp);//��������У���
	int rtn = pcap_sendpacket(Nic, (const u_char*)temp, 74);//�������ݱ�
	if (rtn == 0)
		ltable.log_ip("Resend ", temp);//д����־
}


//����·�ɱ��Ӧ����,��������һ����ip��ַ
DWORD routetable::lookup(DWORD ip)
{
	routeitem* t = head->nextitem;
	for (; t != tail; t = t->nextitem)
	{
		if ((t->mask & ip) == t->net)
			return t->nextip;
	}

	return -1;
}






int log::num = 0;
log log::diary[50] = {};
FILE* log::fp = nullptr;
log::log()
{
	fp = fopen("log.txt", "a+");

}

log::~log()
{
	fclose(fp);
}


void log::print()//��ӡ��־
{
	int i;
	if (num > 50)
		i = (num + 1) % 50;
	else i = 0;
	for (; i < num % 50; i++)
	{
		printf("%d ", diary[i].index);
		printf("%s\t ", diary[i].type);

		if (!strcmp(diary[i].type, "ARP"))
		{
			in_addr addr;
			addr.s_addr = diary[i].arp.ip;
			char* pchar = inet_ntoa(addr);
			printf("%s\t", pchar);
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].arp.mac[i]);
			}
			printf("%02X\n", diary[i].arp.mac[5]);
		}
		else if (!strcmp(diary[i].type, "IP"))
		{
			in_addr addr;
			addr.s_addr = diary[i].ip.sip;
			char* pchar = inet_ntoa(addr);
			printf("SrcIP��%s\t", pchar);
			addr.s_addr = diary[i].ip.dip;
			pchar = inet_ntoa(addr);
			printf("DstIP��%s\t", pchar);
			printf("SrcMAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.smac[i]);
			}
			printf("%02X\t", diary[i].ip.smac[5]);
			printf("DstMAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.dmac[i]);
			}
			printf("%02X\n", diary[i].ip.dmac[5]);
		}
	}
}

void log::log_ip(Data_t* pkt)//ip����
{
	diary[num % 100].index = num++;
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;


	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}

void log::log_ip(const char* a, Data_t* pkt)//ip����
{
	fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");


	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* pchar = inet_ntoa(addr);

	fprintf(fp, "SrcIP�� ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "DstIP�� ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "SrcMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "DstMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}


void log::log_arp(ARPFrame_t* pkt)//arp����
{
	fprintf(fp, "ARP  ");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* pchar = inet_ntoa(addr);
	fprintf(fp, "IP�� ");
	fprintf(fp, "%s  ", pchar);

	fprintf(fp, "MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

}

DWORD WINAPI handle(LPVOID lparam)//����IP���ݰ�������
{
	routetable rtable = *(routetable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header; const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(Nic, &pkt_header, &pkt_data);
			if (rtn)//���յ���Ϣ
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (compare(header->DesMAC, selfmac))//Ŀ��mac���Լ���mac
		{

			if (ntohs(header->FrameType) == 0x800)//IP��ʽ���ݱ�
			{
				Data_t* data = (Data_t*)pkt_data;
				ltable.log_ip("recv", data);//д����־

				DWORD ip1_ = data->IPHeader.DstIP;
				DWORD table_ip = rtable.lookup(ip1_);//�����Ƿ��ж�Ӧ����
				if (table_ip == -1)//���û����ֱ�Ӷ���
					continue;

				if (checkchecksum(data))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))//��Ҫת��
					{
						int t1 = compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							//ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;

							BYTE mac[6];

							if (table_ip == 0) // Ĭ��·�ɣ�ֱ��Ͷ��
							{
								//���ARP����û���������ݣ�����Ҫ��ȡARP
								if (!arptable::lookup(ip1_, mac))
									arptable::insert(ip1_, mac);
								//getmac(mac);
								resend(temp, mac);
							}

							else if (table_ip != -1) //��ֱ��Ͷ�ݣ�������һ��IP��MAC
							{
								if (!arptable::lookup(table_ip, mac))
									arptable::insert(table_ip, mac);

								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}


void ipprint(DWORD ip)//��ӡIP
{
	in_addr addr;
	addr.s_addr = ip;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);
	printf("\n");
}


void setchecksum(Data_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//ȡ��
}
bool checkchecksum(Data_t* temp)//У��
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//����ԭ��У������
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	//printf("%d", (WORD)~temp->IPHeader.Checksum);
	if (sum == 65535)
		return 1;
	return 0;
}




int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6])
{
	atable[num].ip = ip;
	getothermac(ip, atable[num].mac);
	memcpy(mac, atable[num].mac, 6);
	num++;
}
int arptable::lookup(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == atable[i].ip)
		{
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}
	return 0;
}