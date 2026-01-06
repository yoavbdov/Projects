#include <linux/if.h> /*for struct ifreq, provide data structures to manage network interface*/
#include <linux/if_tun.h> /*additional flags to the tun*/
#include <stdio.h> /*for printf*/
#include <fcntl.h> /*for special arguments in open*/
#include <sys/ioctl.h> /*for flags*/
#include <string.h> /*for memset*/
#include <unistd.h> /*for close*/
#include <stdlib.h> /*for system() function*/
#include <sys/socket.h> /*for socket functions*/
#include <sys/types.h> /*for addrinfo*/
#include <netdb.h> /*for addrinfo*/
#include <signal.h> /*for signal catching*/
#include <arpa/inet.h> /*for inet struct*/


struct sockaddr_in server_address;

int tun_fd;

int sock_fd;

int port = 54345;

char *server_ip = "10.1.0.6";


/*a function to create a TUN and return a file descriptor to it(which is the sokcet).*/
int create_tun()
{
    struct ifreq ifr;
        //    struct ifreq {
        //        char ifr_name[IFNAMSIZ]; /* Interface name */
        //        union {
        //            struct sockaddr ifr_addr;
        //            struct sockaddr ifr_dstaddr;
        //            struct sockaddr ifr_broadaddr;
        //            struct sockaddr ifr_netmask;
        //            struct sockaddr ifr_hwaddr;
        //            short           ifr_flags;
        //            int             ifr_ifindex;
        //            int             ifr_metric;
        //            int             ifr_mtu;
        //            struct ifmap    ifr_map;
        //            char            ifr_slave[IFNAMSIZ];
        //            char            ifr_newname[IFNAMSIZ];
        //            char           *ifr_data;
        //        };
        //    };

    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        perror("Cannot open /dev/net/tun");
        return fd;
    }

    /*making sure that all the fields of the struct are set to 0 - so we have a clean start.*/
    memset(&ifr, 0, sizeof(ifr));

    /*Adjusting the flags to make sure the fd will refer to a TUN(and not other kind of interface)*/
    ifr.ifr_flags = IFF_TUN;

    /*setting the interface name to be tun0.*/
    strncpy(ifr.ifr_name, "tun0", sizeof("tun0"));

    int res = 0;
    /*TUNSETIFF stands for TUN set interface flags - this thing sets up the TUN device*/
    if ((res = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        printf("(make sure you run with sudo)\n");
        close(fd);
        return res;
    }

  return fd;
}

/*A function to run a sys-call, and exiting with an error if there's any problemo*/
static void run_command(char *cmd)
{
    printf("executing: `%s`\n", cmd);
    int res = system(cmd);
    if (res != 0)
    {
        printf("Failed to run: %s", cmd);
        exit(1);
    }
}


void ask_ping() 
{
    char dest_ip[16];
    printf("What's your dest ip?");
    scanf("%s", dest_ip);
    char command[100];
    //directing all the traffic to a host go VIA the TUN
    snprintf(command, sizeof(command), "sudo route add -host %s tun0", dest_ip);
    run_command(command);
}



  void configure_routing_table()
  {
    //Enable forwarding ipv4 packets
    run_command("sudo sysctl net.ipv4.ip_forward=1");
    //configure TUN device
    run_command("sudo ifconfig tun0 10.8.0.1/24 up");
    //all the traffic that is sent to this subnet will be routed VIA tun0
    run_command("sudo route add -net 10.8.0.0/24 tun0");

    //all the traffic that the dest ip is 0.0.0.0-127.255.255.255 and 128.0.0.0-255.255.255.255 
    //will be routed VIA tun0. We are using the rule of specification - so we overcome the default gateway
    run_command("sudo ip route add 0.0.0.0/1 via 10.8.0.1 dev tun0");
    run_command("sudo ip route add 128.0.0.0/1 via 10.8.0.1 dev tun0");
  }
   

void cleanup_routing_table()
{
  run_command("iptables -F");
  run_command("iptables -t nat -F");
  close(tun_fd);
  close(sock_fd);
  exit(0);
}




int Create_Socket(char *VPN_server)
{
  int socket_fd;

//initializing the server_address struct to 0.
  memset(&server_address, 0, sizeof(server_address));

//the kind of communication is IPV4
  server_address.sin_family = AF_INET;
//What port do we want to connect on
  server_address.sin_port = htons(port);
//whats the dest ip address?
  server_address.sin_addr.s_addr = inet_addr(server_ip);

//finaly creating the socket - ipv4 and UDP.
  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  return sock_fd;
}

//action handler when there's an update with the sets
void tun_selected(int tunfd, int sockfd) 
{
    int  len;
    char buff[100];

    //initializing the buffer to NULL in all of his bytes
    bzero(buff, sizeof(buff));

    //reading the tun file descriptor to the buffer.
    len = read(tunfd, buff, sizeof(buff));

    //connection between the tun and the socket
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &server_address,
                    sizeof(server_address));
}

//action handler when there's an update with the sets
void socket_selected (int tunfd, int sockfd) 
{
    int len;
    char buff[100];

    //initializing the buffer to NULL in all of his bytes
    bzero(buff, sizeof(buff));
    //receiving data from socket into the buffer
    len = recvfrom(sockfd, buff, sizeof(buff), 0, NULL, NULL);
    //write to the tun file descriptor from the buffer
    write(tunfd, buff, len);

}


int main()
{
  //signal handler for ctl+c
  signal(SIGINT, cleanup_routing_table);

  char *dest_ip;

  if ((tun_fd = create_tun()) < 0)
  {
    return 1;
  }

  configure_routing_table();

  sock_fd = Create_Socket(server_ip);


  //ask_ping(dest_ip);
  


  //continously checking if there's any I/O action in one of the fd in the set
  while(1)
  {
    //creating a set of file descriptors
    fd_set readFDSet;
    
    // initializing the set
    FD_ZERO(&readFDSet);

    //adding to the set those 2 fd
    FD_SET(sock_fd, &readFDSet);
    FD_SET(tun_fd, &readFDSet);
    
    //monitoring for input output activity.
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    if (FD_ISSET(tun_fd,  &readFDSet)) 
    {
      tun_selected(tun_fd, sock_fd);
    }

    if (FD_ISSET(sock_fd, &readFDSet)) 
    {
      socket_selected(tun_fd, sock_fd);
    }
      
  }

  cleanup_routing_table();

  return 0;
}