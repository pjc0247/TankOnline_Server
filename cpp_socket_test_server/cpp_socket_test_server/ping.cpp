#include "stdafx.h"

#include <Windows.h>
#include <stdio.h>

#include <process.h>

#include <map>
using namespace std;

#include "protocol.h"
#include "ping.h"

unsigned int __stdcall PingUpdateThread(void *arg);
void UpdatePing();

unsigned int hPingUpdateThread;

extern struct PER_HANDLE_DATA;
extern map<int,PER_HANDLE_DATA*> clients;
extern void Send(int w,int p,char *m);

unsigned int __stdcall PingUpdateThread(void *arg){
	while(1){
		UpdatePing();
		Sleep(3000);
	}
	return 0;
}

void StartPingUpdate(){
	hPingUpdateThread = _beginthreadex(NULL, 0, PingUpdateThread, NULL, 0, NULL);
}
void StopPingUpdate(){
	_endthreadex(hPingUpdateThread);
}

void UpdatePing(){
	map<int,PER_HANDLE_DATA*>::iterator itor;
	char t[16];
	
	sprintf(t,"%d", GetTickCount64());
	for(itor=clients.begin();itor!=clients.end();++itor){
		Send(itor->first,PING,t);
	}
}
