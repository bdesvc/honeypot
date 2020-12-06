#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

void Strip(char* str){
	str[strcspn(str, "\n")] = '\0'; // Remove \n's
	str[strcspn(str, "\r")] = '\0'; // Remove \r's
}

void SendPrompt(int sockfd, char Username[32], char* Path){
	char Buffer[100];
	sprintf(Buffer, "[%s@dvr %s]$ ", Username, Path);
	write(sockfd, Buffer, strlen(Buffer));
}