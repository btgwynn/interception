#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/param.h>

#include <linux/types.h>
#include <linux/icmp.h>
//#include <linux/ip_fw.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/ipv6.h>

#define IPPROTO_DIVERT 254
#define BUFSIZE 65535

char *progname;

#ifdef FIREWALL

char *fw_policy="DIVERT";
char *fw_chain="output";
struct ip_fw fw;
struct ip_fwuser ipfu;
struct ip_fwchange ipfc;
int fw_sock;

/* remove the firewall rule when exit */
void intHandler (int signo) {

  if (setsockopt(fw_sock, IPPROTO_IPV6, IP_FW_DELETE, &ipfc, sizeof(ipfc))==-1) {
    fprintf(stderr, "%s: could not remove rule: %s\n", progname, strerror(errno));
    exit(2);
  }

  close(fw_sock);
  exit(0);
}

#endif

int main(int argc, char** argv) {
  int fd, rawfd, fdfw, ret, n;
  int on=1;
  struct sockaddr_in6 bindPort, sin;
  int sinlen;
  struct ipv6hdr *hdr;
  unsigned char packet[BUFSIZE];
  struct in6_addr addr;
  int i, direction;
  struct ip_mreq mreq;
  
  char str6[INET6_ADDRSTRLEN];

  if (argc!=2) {
    fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
    exit(1); 
  }
  progname=argv[0];

  fprintf(stderr,"%s:Creating a socket\n",argv[0]);
  /* open a divert socket */
  fd=socket(AF_INET6, SOCK_RAW, IPPROTO_DIVERT);

  if (fd==-1) {
    fprintf(stderr,"%s:We could not open a divert socket\n",argv[0]);
    exit(1);
  }

  bindPort.sin6_family=AF_INET6;
  bindPort.sin6_port=htons(atol(argv[1]));
  inet_pton(AF_INET6, "::1", &bindPort.sin6_addr);

  fprintf(stderr,"%s:Binding a socket\n",argv[0]);
  ret=bind(fd, (struct sockaddr*)&bindPort, sizeof(struct sockaddr_in6));

  if (ret!=0) {
    close(fd);
    fprintf(stderr, "%s: Error bind(): %s",argv[0],strerror(ret));
    exit(2);
  }
#ifdef FIREWALL
  /* fill in the rule first */
  bzero(&fw, sizeof (struct ip_fw));
  fw.fw_proto=1; /* ICMP */
  fw.fw_redirpt=htons(bindPort.sin6_port);
  fw.fw_spts[1]=0xffff;
  fw.fw_dpts[1]=0xffff;
  fw.fw_outputsize=0xffff;

  /* fill in the fwuser structure */
  ipfu.ipfw=fw;
  memcpy(ipfu.label, fw_policy, strlen(fw_policy));

  /* fill in the fwchange structure */
  ipfc.fwc_rule=ipfu;
  memcpy(ipfc.fwc_label, fw_chain, strlen(fw_chain));

  /* open a socket */
  if ((fw_sock=socket(AF_INET6, SOCK_RAW, IPPROTO_RAW))==-1) {
    fprintf(stderr, "%s: could not create a raw socket: %s\n", argv[0], strerror(errno));
    exit(2);
  }

  /* write a rule into it */
  if (setsockopt(fw_sock, IPPROTO_IPV6, IP_FW_APPEND, &ipfc, sizeof(ipfc))==-1) {
    fprintf(stderr, "%s could not set rule: %s\n", argv[0], strerror(errno));
    exit(2);
  }
 
  /* install signal handler to delete the rule */
  signal(SIGINT, intHandler);
#endif /* FIREWALL */
  
  printf("%s: Waiting for data...\n",argv[0]);
  /* read data in */
  sinlen=sizeof(struct sockaddr_in6);
  while(1) {
    n=recvfrom(fd, packet, BUFSIZE, 0, (struct sockaddr*)&sin, &sinlen);
    hdr=(struct ipv6hdr*)packet;
    
    printf("%s: The packet looks like this:\n",argv[0]);
        for( i=0; i<40; i++) {
                printf("%02x ", (int)*(packet+i));
                if (!((i+1)%16)) printf("\n");
        };
    printf("\n"); 

    addr=hdr->saddr;
    inet_ntop(AF_INET6, &addr,str6,sizeof(str6));
    printf("%s: Source address: %s\n",argv[0], str6);
    addr=hdr->daddr;
    inet_ntop(AF_INET6, &addr,str6,sizeof(str6));
    printf("%s: Destination address: %s\n", argv[0], str6);
    inet_ntop(AF_INET6, &sin.sin6_addr,str6,sizeof(str6));
    printf("%s: Receiving IF address: %s\n", argv[0], str6);
    //printf("%s: Protocol number: %i\n", argv[0], hdr->protocol);

    /* reinjection */

#ifdef MULTICAST 
   if (IN_MULTICAST((ntohl(hdr->daddr)))) {
        printf("%s: Multicast address!\n", argv[0]);
        addr = hdr->saddr;
        errno = 0;
        if (sin.sin6_addr == 0)
            printf("%s: set_interface returns %i with errno =%i\n", argv[0], setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)), errno);
    }
#endif

#ifdef REINJECT
   printf("%s Reinjecting DIVERT %i bytes\n", argv[0], n);
   n=sendto(fd, packet, n ,0, &sin, sinlen);
   printf("%s: %i bytes reinjected.\n", argv[0], n); 

   if (n<=0) 
     printf("%s: Oops: errno = %i\n", argv[0], errno);
   if (errno == EBADRQC)
     printf("errno == EBADRQC\n");
   if (errno == ENETUNREACH)
     printf("errno == ENETUNREACH\n");
#endif
  }
}

