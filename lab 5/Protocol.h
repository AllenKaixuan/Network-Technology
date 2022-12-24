#pragma once
#include "pcap.h"
#pragma pack(1)//��1byte��ʽ����

//�����ײ�
typedef struct FrameHeader_t {//֡�ײ�
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

//ARP���ĸ�ʽ
typedef struct ARPFrame_t {//IP�ײ�
	FrameHeader_t FrameHeader;//֡�ײ�
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ
	WORD Operation;//����
	BYTE SendHa[6];//���ͷ�MAC
	DWORD SendIP;//���ͷ�IP
	BYTE RecvHa[6];//���շ�MAC
	DWORD RecvIP;//���շ�IP
}ARPFrame_t;

//IP�����ײ�
typedef struct IPHeader_t {//IP�ײ�
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//��������
	BYTE Protocol;
	WORD Checksum;//У���
	ULONG SrcIP;//ԴIP
	ULONG DstIP;//Ŀ��IP
}IPHeader_t;

typedef struct Data_t {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;//֡�ײ�
	IPHeader_t IPHeader;//IP�ײ�
}Data_t;


typedef struct ICMP {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()//�ָ�4bytes����

#pragma pack(1)//��1byte��ʽ����

//·�ɱ����
class routeitem
{
public:
	DWORD mask;//����
	DWORD net;//Ŀ������
	DWORD nextip;//��һ��
	BYTE nextMAC[6];//��һ����MAC��ַ
	int index;//�ڼ���
	int type;
	routeitem* nextitem;
	routeitem()
	{
		memset(this, 0, sizeof(*this));
	}
	void printitem();//��ӡ�������ݣ���ӡ�����롢Ŀ���������һ��IP�����ͣ��Ƿ���ֱ�� Ͷ�ݣ�

};

#pragma pack()//�ָ�4bytes����

#pragma pack(1)//�ָ�4bytes����
class routetable
{
public:
	routeitem* head, * tail;
	int num;//����
	routetable();//��ʼ�������ֱ�����ӵ�����
	//·�ɱ����ӣ�ֱ��Ͷ������ǰ��ǰ׺������ǰ��
	void add(routeitem* a);
	//ɾ����type=0����ɾ��
	void remove(int index);
	//·�ɱ�Ĵ�ӡ mask net next type
	void print();
	//���ң��ǰ׺,������һ����ip
	DWORD lookup(DWORD ip);

};
#pragma pack()//�ָ�4bytes����



class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};


class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};


class arptable
{
public:
	DWORD ip;//IP��ַ
	BYTE mac[6];//MAC��ַ
	static int num;//��������
	static void insert(DWORD ip, BYTE mac[6]);//�������
	static int lookup(DWORD ip, BYTE mac[6]);//ɾ������
}atable[50];


//��־��
class log
{
public:
	int index;//����
	char type[5];//arp��ip
	//��������
	ipitem ip; 
	arpitem arp;

	log();
	~log();

	static int num;//����
	static log diary[50];//��־
	static FILE* fp;
	//д����־
	static void log_ip(Data_t*);//ip����
	static void log_arp(ARPFrame_t*);//arp����
	static void log_ip(const char* a, Data_t*);//ip����

	static void print();//��ӡ��־
};
pcap_if_t* alldevs;
pcap_if_t* dev;
pcap_t* Nic;//open������
pcap_addr* a;//������Ӧ�ĵ�ַ
char errbuf[PCAP_ERRBUF_SIZE];
char* pcap_src_if_string;

pcap_if_t* net[10];
char ip[10][20];
char mask[10][20];
BYTE selfmac[6];
char name[100];


BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
int compare(BYTE a[], BYTE b[]);//�Ƚ����������Ƿ���ͬ


//��ȡ�Լ���IP
void find_alldevs();	//��ȡ�������豸�б�������ip����ip������,��ȡIP��mask��������������
DWORD getnet(DWORD ip, DWORD mask);//����ip�����������������
//������ӿ�
pcap_t* open(char* name);
//��ȡ�Լ���MAC
void getselfmac(DWORD ip);
//��ȡֱ�����ӵ�����mac



//�������ݱ���д����־
int iprecv(pcap_pkthdr* pkt_header, const u_char* pkt_data);
//���ݱ�ת��,�޸�Դmac��Ŀ��mac
void resend(ICMP_t, BYTE dmac[]);
//��ӡmac
void getmac(BYTE MAC[]);


DWORD WINAPI handle(LPVOID lparam);
void ipprint(DWORD ip);
bool checkchecksum(Data_t*);
void setchecksum(Data_t*);