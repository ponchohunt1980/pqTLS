// Server 

#include <stdio.h> 
#include <unistd.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 

#include "pq.h"

#define PORT 7070 
#define NSB  1024
#define FSERVER 1 // and FCLIENT 0

//argv[2] = 0 no sign || argv[2] = 1 server cert verify || argv[2] = 2 both verify
int main(int argc, char const *argv[]) 
{ 
    int server_fd, new_socket, lenval; 
    struct sockaddr_in address; 
    int optval = 1; 
    int addrlen = sizeof(address); 
    char opt[NSB]; 
    int opt2;
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 7070 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &optval, sizeof(optval))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    }

    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 7070 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 

    while(1)
    {
        if (listen(server_fd, 3) < 0) 
        { 
            perror("listen"); 
            exit(EXIT_FAILURE); 
        }

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                           (socklen_t*)&addrlen))<0) 
        { 
            perror("accept"); 
            exit(EXIT_FAILURE); 
        }

        lenval = read(new_socket, opt, NSB); 
        opt[lenval] = '\0'; 
        lenval = read(new_socket, &opt2, sizeof(opt2)); 

        TLS(new_socket, opt, opt2, FSERVER); //TLS func -> pq.c

        fflush(stdout);
        opt[0] = '\0';
    }

    return 0; 
} 
