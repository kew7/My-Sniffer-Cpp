// пример с сайта https://www.programmersforum.ru/showthread.php?t=322382, несколько переделанныЙ
/*
1: Ловит один IP пакет;
2: Показывает его заголовок(версия, длина, флаги и т.д.);
3: Показывает его даннные
*/

#include <iostream>
#include <conio.h>
#include <winsock2.h>
#include <bitset>
#include <mstcpip.h>

//#define SIO_RCVALL         0x98000001

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
	char Buffer[65535];
	WSABUF  wBuf;
	DWORD   dwBytesRet,
		    dwFlags=0;
			wBuf.len = 65535;
			wBuf.buf = Buffer;

	cout << "Start...\n";
	if (WSAStartup(MAKEWORD(2, 2), &WSData) != 0)  // загружаем библиотеку 
	{
		cout << "Error loading WSA";
		return FALSE;
	}

	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(name, sizeof(name));
	phe = gethostbyname(name);
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr*)phe->h_addr_list[0])->s_addr;
	if (bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		cout << "Error bind";
		getchar();
		exit(1);
	}

	// Using WSAIoctl function controls the mode of a socket
	// The SIO_RCVALL control code enables a socket to receive all IPv4 or IPv6 packets passing through a network interface

	/******************* ПЕРВЫЙ ВАРИАНТ устаревший, но рабочий **********************/ 
	/*if (ioctlsocket(s, SIO_RCVALL, &flag) == SOCKET_ERROR)
	{
		cout << "WSAIoctl error";
		cout << WSAGetLastError();
	}*/

	/*******************  ВТОРОЙ ВАРИАНТ  ********************/
	RCVALL_VALUE mRCVAL = RCVALL_IPLEVEL;		// перехватываем только IP-пакеты, подробнее см.RCVALL_VALUE
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

	while (!_kbhit()) // до нажатия любой клавиши
	{
		count = recv(s, Buffer, sizeof(Buffer), 0);
		//count = WSARecv(s, &wBuf, 1, &dwBytesRet, &dwFlags, NULL, NULL);
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


// ===================================//
		// ИСХОДНАЯ ПРОГРАММА
/*
#include <conio.h>
#include <stdio.h>
#include <winsock2.h>
#include <ntverp.h>
//#include <stdafx.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")


#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL         0x98000001
// Буфер для приёма данных
char Buffer[MAX_PACKET_SIZE]; // 64 Kb

//Структура заголовка IP-пакета

typedef struct IPHeader {
	UCHAR   iph_verlen;   // версия и длина заголовка
	UCHAR   iph_tos;      // тип сервиса
	USHORT  iph_length;   // длина всего пакета
	USHORT  iph_id;       // Идентификация
	USHORT  iph_offset;   // флаги и смещения
	UCHAR   iph_ttl;      // время жизни пакета
	UCHAR   iph_protocol; // протокол
	USHORT  iph_xsum;     // контрольная сумма
	ULONG   iph_src;      // IP-адрес отправителя
	ULONG   iph_dest;     // IP-адрес назначения
} IPHeader;

char src[10];
char dest[10];
char ds[15];
unsigned short lowbyte;
unsigned short hibyte;

void main()
{
	WSADATA     wsadata;   // Инициализация WinSock.
	SOCKET      s;         // Cлущающий сокет.
	char       name[128]; // Имя хоста (компьютера).
	struct hostent* phe;       // Информация о хосте.
	SOCKADDR_IN sa;        // Адрес хоста
	IN_ADDR sa1;        //
	unsigned long        flag = 1;  // Флаг PROMISC Вкл/выкл.

	// инициализация
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	
	gethostname(name, sizeof(name));
	phe = gethostbyname(name);

	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr*)phe->h_addr_list[0])->s_addr;
	bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR));

	// Включение promiscuous mode.
	ioctlsocket(s, IOC_VOID, &flag);

	// Бесконечный цикл приёма IP-пакетов.
	while (!_kbhit())
	{
		int count;
		count = recv(s, Buffer, sizeof(Buffer), 0);
		// обработка IP-пакета
		if (count >= sizeof(IPHeader))
		{
			IPHeader* hdr = (IPHeader*)Buffer;
			//Начинаем разбор пакета...

			strcpy_s(src, "Пакет: ");
			CharToOem((LPCWSTR)src, dest);
			printf(dest);
			// Преобразуем в понятный вид адрес отправителя.
			printf("From ");
			sa1.s_addr = hdr->iph_src;
			printf(inet_ntoa(sa1));

			// Преобразуем в понятный вид адрес получателя.
			printf(" To ");
			sa1.s_addr = hdr->iph_dest;
			printf(inet_ntoa(sa1));

			// Вычисляем протокол. Полный список этих констант
			// содержится в файле winsock2.h
			printf(" Prot: ");
			if (hdr->iph_protocol == IPPROTO_TCP) printf("TCP ");
			if (hdr->iph_protocol == IPPROTO_UDP) printf("UDP ");

			// Вычисляем размер. Так как в сети принят прямой порядок
			// байтов, а не обратный, то прийдётся поменять байты местами.
			printf("Size: ");
			lowbyte = hdr->iph_length >> 8;
			hibyte = hdr->iph_length << 8;
			hibyte = hibyte + lowbyte;
			printf("%s", itoa(hibyte, ds, 10));

			// Вычисляем время жизни пакета.
			printf(" TTL:%s",itoa(hdr->iph_ttl,ds,10));
			// printf(" TTL:%s", _itoa(hdr->iph_ttl, ds, 10));
			printf("\n");

		}
	}

	closesocket(s);
	WSACleanup();
}
*/