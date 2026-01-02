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

#define PORT_NUMBER 54345
struct sockaddr_in server_address;
int tun_fd;
int sock_fd;
char *client_ip = "10.1.0.32";



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
    /*TUNSETIFF stand for TUN set interface flags - this thing sets up the TUN device*/
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




  void configure_routing_table()
  {
    run_command("sudo sysctl net.ipv4.ip_forward=1");
    run_command("sudo ifconfig tun0 10.8.0.2/24 up");
    run_command("sudo route add -net 10.8.0.0/24 tun0");

    run_command("iptables -t nat -A POSTROUTING -o enp0s3 -s 10.8.0.1/24 -j MASQUERADE");
  }

void cleanup_routing_table()
{
  run_command("iptables -F");
  run_command("iptables -t nat -F");
  close(tun_fd);
  close(sock_fd);
  exit(0);
}




int init_UDP_server()
{
  int sock_fd;

  struct sockaddr_in server;


  char buff[100];

  memset(&server, 0, sizeof(server));

  server.sin_family = AF_INET;

  //making the sock available for any IP of our machine(a macro when we use when we dont know the specific ip yet)
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  server.sin_port = htons(PORT_NUMBER);

  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  //binding meaning that we bind that socket to OUR ip and OUR port, and we are ready to listen on this port.
  bind(sock_fd, (struct sockaddr*) &server, sizeof(server));

  bzero(buff, 100);
  int peer_addr_len = sizeof(struct sockaddr_in);


  /*
    arguments:
    1)socket fd
    2)where to store the data
    3)how much data to read
    4)flags(not needed here)
    5)pointer to the socket structure which has information about it.
    6)pointer to the size of the structure
  */
  recvfrom(sock_fd, buff, 100, 0, (struct sockaddr *) &server_address, &peer_addr_len);


  return sock_fd;
}


void tun_selected(int tunfd, int sockfd) {
    int  len;
    char buff[100];

    //initializing the buffer to NULL in all of his bytes
    bzero(buff, sizeof(buff));

    //reading the tun file descriptor to the buffer.
    len = read(tunfd, buff, sizeof(buff));

    //sending data from the buffer of length len through the socket identified by sockfd to the server_address
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &server_address,
                    sizeof(server_address));
}


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

  signal(SIGINT, cleanup_routing_table);

  char *dest_ip;

  if ((tun_fd = create_tun()) < 0)
  {
    return 1;
  }

  configure_routing_table();

  sock_fd = init_UDP_server(client_ip);


  
  while(1)
  {
    //creating a set of file descriptors
    fd_set readFDSet;
    
    //initializing the set
    FD_ZERO(&readFDSet);

    //adding to the set those 2 fd
    FD_SET(sock_fd, &readFDSet);
    FD_SET(tun_fd, &readFDSet);
    

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