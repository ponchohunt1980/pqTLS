// Client 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 

#include "pq.h"

#define PORT 7070 
#define NSB  1024
#define FCLIENT 0 // and FSERVER 1
   
int main(int argc, char const *argv[]) 
{ 
    int sock = 0, lenval; 
    struct sockaddr_in serv_addr; 
    char sbuffer[NSB] = {0}; 
    char opt[NSB]; 

    if (argc < 2)
    {
        printf("USO: ./program options\n");
        return -1;
    }

    memcpy(opt, argv[1], strlen(argv[1]));

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "148.204.64.8", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 

    send(sock, opt, strlen(opt), 0);

    TLS(sock, opt, FCLIENT);

    fflush(stdout);
    opt[0] = '\0';

    return 0; 
}
