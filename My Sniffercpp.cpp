
#define MAX_IP_SIZE        65535

#include <iostream>
#include <conio.h>
#include <winsock2.h>
#include <bitset>
#include <mstcpip.h>

using namespace std;

typedef struct IPPacket //Структура ip пакета
{
	unsigned char  ip_ver_hlen;		// версия IP и длина заголовка по 4 бита
	unsigned char  ip_tos;			// тип сервиса
	unsigned short ip_length;		// длина пакета
	unsigned short ip_id;
	unsigned short ip_flag_offset;
	unsigned char  ip_ttl;
	unsigned char  ip_protocol;
	unsigned short ip_xsum;
	unsigned int   ip_srcaddr;
	unsigned int   ip_dstaddr;
	char  ip_data[];
};

typedef struct TCPHeader // Структура TCP заголовка
{
	unsigned short tcp_srcport;
	unsigned short tcp_dstport;
	unsigned int tcp_sn;
	unsigned int tcp_acksn;
	unsigned char tcp_hlen : 4;
	unsigned char tcp_flag_offset : 6;
	unsigned char tcp_flags : 6;
	unsigned short tcp_window;
	unsigned short tcp_xsum;
	unsigned short tcp_urg_pointer;
	char tcp_opt_data[];
};

typedef struct UDPHeader // Структура UDP заголовка
{
	unsigned short udp_srcport;
	unsigned short udp_dstport;
	unsigned short udp_length;
	unsigned short udp_xsum;
	unsigned char  udp_data[];
};

void ShowPacketInfo(IPPacket* iph) {			// Информация об IP пакете
	cout << "Version: " << (static_cast<int>(iph->ip_ver_hlen)>>4) << endl;
	cout << "Header length: " << static_cast<int>(iph->ip_ver_hlen&0x0F)*4 << endl; 
	cout << "ToS: " << bitset<8>(iph->ip_tos) << endl;
	cout << "Packet length: " << htons(iph->ip_length) << endl;
	cout << "Id: " << iph->ip_id << endl;
	cout << "Flags: " << bitset<3>(iph->ip_flag_offset >> 13) << endl;
	cout << "Offset: " << bitset<13>(iph->ip_flag_offset & 8191) << endl;
	cout << "TTL: " << static_cast<int>(iph->ip_ttl) << endl;
	cout << "Protocol: ";
	switch (iph->ip_protocol) {
	case IPPROTO_TCP:
		cout << "TCP";
		break;
	case IPPROTO_UDP:
		cout << "UDP";
		break;
	default:
		cout << "Unknown";
		break;
	}
	cout << endl;
	cout << "Xsum: " << iph->ip_xsum << endl;
	IN_ADDR sa;
	sa.s_addr = iph->ip_srcaddr;
	cout << "Src: " << inet_ntoa(sa) << endl;
	sa.s_addr = iph->ip_dstaddr;
	cout << "Dst: " << inet_ntoa(sa) << endl;
}

void ShowPacketData(IPPacket* iph, int type) {		// Данные IP пакета
	char bf[2];
	cout << "IPData: " << endl;
	if (type == 1) {	//HEX
		for (int i = 0; i < htons(iph->ip_length); i++) {

			itoa(static_cast<short>(iph->ip_data[i]), bf, 16);
			if (bf[1] == 0) {
				bf[1] = bf[0];
				bf[0] = '0';
			}
			cout << bf << ' ';

			if ((i % 16 == 0) && (i != 0)) {
				cout << endl;
			}
		}
	}
	else {		//char
		for (int i = 0; i < htons(iph->ip_length); i++) {
			if (iph->ip_data[i] == 0) {
				cout << '.';
			}
			else {
				cout << iph->ip_data[i];
			}
			if ((i % 64 == 0) && (i != 0)) {
				cout << endl;
			}
		}
	}
	cout << endl;
}

int main(int argc, char* argv[])
{
	WSAData WSData;
	SOCKET s;
	char name[128];
	HOSTENT* phe;
	SOCKADDR_IN sa;
	unsigned long flag = 1;
	char Buffer[MAX_IP_SIZE];
	WSABUF  wBuf;
	DWORD   dwBytesRet,
		    dwFlags = 0;
			wBuf.len = MAX_IP_SIZE;
			wBuf.buf = Buffer;
	int nIPtemp;

	// кодировка
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	cout << "Start...\n";
	if (WSAStartup(MAKEWORD(2, 2), &WSData) != 0)  // загружаем библиотеку Winsock2
	{
		cout << "Error loading WSA";
		return FALSE;
	}

	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(name, sizeof(name));
	phe = gethostbyname(name);
	ZeroMemory(&sa, sizeof(sa));
	
	// IP-адреса устройств
	USHORT nCountIPadr =0; // количество ненулевых IP-адресов
	cout << "Список доступных IP-адресов:" << endl;
	for (int i = 0; phe->h_addr_list[i] != 0; ++i) {
		cout << i+1 << ". " << inet_ntoa(*(struct in_addr*)phe->h_addr_list[i]) << endl; 
		nCountIPadr++;
	}
	cout << endl;
	cout << "Count of IP adress = " << nCountIPadr << endl << endl;

////////////////////////////////
LABEL: // метка при неправильном вводе
	cout << "Enter Number of IP-adress: ";	// номер IP-адреса из списка
	cin >> nIPtemp;

	if ((nIPtemp > 0) && (nIPtemp <= nCountIPadr))
	{
		nIPtemp = nIPtemp--; 
		cout << "Ок...\n\n" << endl;
	} // уменьшаем на 1 с учетом индексации массива
	else 
		goto LABEL; 
////////////////////////////////

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr*)phe->h_addr_list[nIPtemp])->s_addr;

	if (bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		cout << "Error bind";
		getchar();
		exit(1);
	}

	/*******************  Использование фунции WSAIoctl  ********************/
	RCVALL_VALUE mRCVAL = RCVALL_IPLEVEL;		// только IP-пакеты, подробнее см.RCVALL_VALUE
	DWORD lpcbBytesReturned;
	if (WSAIoctl(s, SIO_RCVALL, &mRCVAL, sizeof(mRCVAL), NULL, 0, &lpcbBytesReturned,
				NULL, NULL) == SOCKET_ERROR)
	{
		int Error = WSAGetLastError();
		cout << "Error code of <WSAIoctl>: " << Error << endl;
		exit(Error);
	};

	int count = 0;
	int c = 0;
	IPPacket* iph = (IPPacket*)Buffer;

	while (!kbhit()) // до нажатия любой клавиши
	{
		count = recv(s, Buffer, sizeof(Buffer), 0);
		if (count == SOCKET_ERROR) cout << "Ошибка WSARecv";
		if (count >= sizeof(IPPacket))
		{
			ShowPacketInfo(iph);
			//ShowPacketData(iph, 0);
			if (iph->ip_protocol == IPPROTO_TCP) {
				TCPHeader* tcp = (TCPHeader*)iph->ip_data;
				// Вывод №№ портов TCP
				cout << "TCP-port Src->Dst: " << htons(tcp->tcp_srcport)<<"->"<<htons(tcp->tcp_dstport) << endl << endl;
			}
			if (iph->ip_protocol == IPPROTO_UDP) {
				UDPHeader* udp = (UDPHeader*)iph->ip_data;
				// Вывод №№ портов UDP
				cout << "UDP-port Src->Dst: " << htons(udp->udp_srcport)<<"->"<<htons(udp->udp_dstport) << endl << endl;
			}
		}
		Sleep(100);
	}
	closesocket(s);
	WSACleanup();
	return 0;
}


