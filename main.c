#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>

#include "utils.h"
#include "structs.h"
#include "strings.h"

struct honeypot_t Honeypots[]; // define array for honeypot clients instead of passing structs
char* Paths[]; // define current paths for each user/malware

int connCounter = 0; // define connection counter

void* System(int id)
{
	struct creds_t credentials; // initialize credentials
	struct honeypot_t honeypot = Honeypots[id]; // get honeypot user info

	char ConnBuffer[1024]; // define read buffer
	read(honeypot.fd, &ConnBuffer, 1024); // read

	write(honeypot.fd, "dvr login: ", strlen("dvr login: ")); // send dvr login
	read(honeypot.fd, &credentials.username, 32); // read username

	Strip(&credentials.username); // strip username



	write(honeypot.fd, "password: ", strlen("password: ")); // send password
	read(honeypot.fd, &credentials.password, 32); // read password


	Strip(&credentials.password); // strip password

	if(credentials.password[0] == '\0' || credentials.username[0] == '\0') // check if either strings are empty
	{
		write(honeypot.fd, "\n\nLogin failed\r\n", strlen("\n\nLogin failed\r\n")); // send login empty
		sleep(3); // wait 3 seconds
		shutdown(honeypot.fd, 2); // shutdown socket
		pthread_exit(NULL); // kill thread
	}

	Paths[honeypot.fd] = "/"; // set path

	write(honeypot.fd, BusyBox, strlen(BusyBox)); // send busybox intro

	while(1) // while 1
	{
		char Data[1024]; // define buffer for input with size of 1024

		SendPrompt(honeypot.fd, credentials.username, Paths[honeypot.fd]); // send prompt defined in utils.h
		read(honeypot.fd, Data, 1024); // read data

		Strip(&Data); // strip data

		char* Args[1024]; // define char* array with size of 1024

		char* token = strtok(Data, " "); // find next " "
		size_t i = 0; // define i as 0
		while(token != NULL) // while token isn't null
		{
			Args[i] = token; // add argument to array
			i++; // add 1 to i
			token = strtok(NULL, " "); // find next token
		}

		if(i != 0) // if arguments (i) is not 0
		{
			if(strstr(Args[0], "clear")) // if argument 0 contains clear
			{
				write(honeypot.fd, "\033[2J\033[H", strlen("\033[2J\033[H")); // send ascii clear screen
				write(honeypot.fd, BusyBox, strlen(BusyBox)); // send busybox intro
			}
			if(strstr(Args[0], "cd")) // if argument 0 contains cd
			{
				if(i == 2) // if 1 argument was giving cd path, etc.
				{
					if(strstr(Args[1], "..")) // check if its dot to return
					{
						Paths[honeypot.fd] = "/"; // set path to default
					}
					else // if its not .. set new path
					{
						Paths[honeypot.fd] = Args[1]; // set path to argument 1
					}
				}
			}
			if(strstr(Args[0], "wget")) // if argument 0 contains wget
			{
				write(honeypot.fd, WGet, strlen(WGet)); // send wget string defined in strings.h
			}
			if(strstr(Args[0], "ls")) // if argument 0 contains ls
			{
				if(strstr(Paths[honeypot.fd], "/")) // write the list of fake files in / directory
				{
					write(honeypot.fd, ListFiles, strlen(ListFiles)); // send fake files
				}
				else // if its not /
				{
					write(honeypot.fd, "\r\n", strlen("\r\n")); // send newline because its a empty folder
				}
			}
		}
	}
}

void* InitializeHoneypot(int port)
{
	int listen_fd, connection_fd, length; // define sockets
	struct sockaddr_in server_addr, client; // define server address and client address

	printf("[honeypot] starting service..\n"); // print that honeypot service is starting to backend
	listen_fd = socket(AF_INET, SOCK_STREAM, 0); // Initialize a socket for IPv4 via TCP
	if(listen_fd == -1)  
	{
		printf("[honeypot] failed to create socket!\n"); // print that it failed to create socket to backend
		exit(0); // shutdown process
	}
	else
	{
		printf("[honeypot] created socket!\n"); // print that it created a socket successfully to backend
	}

	bzero(&server_addr, sizeof(server_addr)); // zero server_addr's memory context

	server_addr.sin_family = AF_INET; // Sets it to AF_INET / IPv4
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Select any local ip
	server_addr.sin_port = htons(port); // argv[1] -> port

	if((bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr))) != 0) // bind the server address to the listening socket
	{
		printf("[honeypot] failed to bind!\n"); // print failed to bind to the backend
		exit(0); // shutdown process
	}
	else
	{
		printf("[honeypot] successfully binded to 0.0.0.0:%i\n", port); // print that it binded successfully to backend
	}

	if((listen(listen_fd, 10)) != 0) // Start listening
	{
		printf("[honeypot] failed to start listening!\n"); // prints that is failed to listen to backend
		exit(0); // shutdown process
	}
	else
	{
		printf("[honeypot] started listening!\n"); // print that i started to listen
	}

	length = sizeof(client); // sets length to size of client address


	while(1){
		connection_fd = accept(listen_fd, (struct sockaddr*)&client, &length); // accept connection
		if(connection_fd == 0)
		{
			printf("[%i] [honeypot] failed to accept connection\n", time(NULL)); // print that honeypot failed to accept connection to backend
		}
		else
		{
			connCounter++;
			printf("[%i] [honeypot] new connection %p\n", time(NULL), connection_fd); // print that it got a new device to backend

			struct honeypot_t honeypot;
			honeypot.fd = connection_fd;
			honeypot.connected_at = time(NULL);

			Honeypots[connCounter] = honeypot;

			pthread_t id; // define pthread_t for the user/malware thread
			pthread_create(&id, 0, &System, connCounter); // create thread for user/malware
		}	
	}
}

int main(int argc, char** argv)
{
	if(argc == 2)
	{
		InitializeHoneypot(atoi(argv[1])); // start on specified port
	}
	else
	{
		InitializeHoneypot(23); // start on default telnet port
	}
}
