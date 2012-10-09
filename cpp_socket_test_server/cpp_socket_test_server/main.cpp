#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <winsock2.h>
 
#include <iostream>
#include <vector>
#include <map>
#include <string>

#include <conio.h>

#include "protocol.h"
#include "blacklist.h"
#include "weblog.h"
#include "ping.h"

#include "database.h"

using namespace std;
 
#define BUFSIZE (1024 * 20)
#define SERVER_PORT 9916 



enum VAR_TYPE {
		VAR_INT,
		VAR_CHAR,
		VAR_FLOAT,
		VAR_STRING
		};
typedef struct
{
	union {
		int i;
		float f;
		char c;
		char *s;
	} data;
	unsigned char type;
} VAR, *LPVAR;
	
typedef struct
{
	char id[32];
	char pw[128];
	char nick[32];

	int x,y,speed;

	bool joined;
	char area[32];

	Database *db;
	map<string,LPVAR> var;
} USER_DATA, *LPUSER_DATA;
typedef struct
{
	SOCKET      hClntSock;
	SOCKADDR_IN clntAddr;
	int n;
	USER_DATA user;

	char ping;

	int fileReceived;
	char fileName[256];
	int fileLength;
	bool fileRecv;
	FILE *filePointer;
	int fileWritten;
} PER_HANDLE_DATA, *LPPER_HANDLE_DATA;

typedef struct
{
	OVERLAPPED overlapped;
	char buffer[BUFSIZE];
	WSABUF wsaBuf;
} PER_IO_DATA, *LPPER_IO_DATA;

typedef struct
{
	void (*handler)(int ,char *);
} HANDLER;


unsigned int __stdcall ControlThread(void *arg);
unsigned int __stdcall CompletionThread(void* CompletionPortIO);
void RegistHandler(int code,void (*cb)(int,char *));
void ParsePacket(int w,char *msg,int msgLength);
void Send(int w,int p,char *msg);
void SendBinary(int w,int p,char *data,int len);
void SendFile(int w,char *file);
void SendVarNew(int w,int t,char *name,int type);
void SendVarDelete(int w,int t,char *name);
void SendVarChange(int w,int t,char *name,int v);
void SendVarChange(int w,int t,char *name,float v);
void SendVarChange(int w,int t,char *name,char v);
void SendVarChange(int w,int t,char *name,char *v);

//vector<PER_HANDLE_DATA*> clients;
map<int,PER_HANDLE_DATA*> clients;
map<int,HANDLER> handler;
map<string,int> session;

map<string,vector<PER_HANDLE_DATA*>> area;

CRITICAL_SECTION csClients;
CRITICAL_SECTION csSession;
CRITICAL_SECTION csArea;

unsigned long uptime_st;
unsigned int ping_update_st;

//#define __SYNCRONIZE
#ifdef	__SYNCRONIZE
	#define __ENTER(cs) EnterCriticalSection(&cs)
	#define __LEAVE(cs) LeaveCriticalSection(&cs)
#else
	#define __ENTER(cs) // do nothing
	#define __LEAVE(cs) // do nothing
#endif//__SYNCRONIZE



bool isSessionOpened(char *id){
	map<string,int>::iterator itor;
	bool find = false;

	__ENTER(csSession);
	for(itor=session.begin();itor!=session.end();++itor){
		if(itor->first == string(id)){
			find = true;
			break;
		}
	}
	__LEAVE(csSession);
	return find;
}
void BroadcastArea(char *_area,int p,char *msg,int exclude=-1){
	vector<PER_HANDLE_DATA*> &Area = area[string(_area)];

	output("broadcast %s\n", msg);
	__ENTER(csArea);
	for(int i=0;i<Area.size();i++){
		if(Area[i]->n == exclude)
			continue;
		Send(Area[i]->n,p,msg);
	}
	__LEAVE(csArea);
}
void Broadcast(int p,char *msg,int exclude=-1){
	output("broadcast(all) %s\n", msg);
	
	/*for(int i=0;i<clients.size();i++){
		if(clients[i]->n == exclude)
			continue;
		Send(clients[i]->n,p,msg);
	}*/
	map<int,PER_HANDLE_DATA*>::iterator itor;
	for(itor=clients.begin();itor!=clients.end();++itor){
		if(itor->second->n == exclude)
			continue;
		Send(itor->second->n,p,msg);
	}
}

void onChatArea(int w,char *msg){
	char packet[256];
	sprintf(packet,"%s��%s",clients[w]->user.nick,msg);
	BroadcastArea(clients[w]->user.area,CHAT_AREA,packet,w);
}
void onChatChannel(int w,char *msg){
	char packet[256];
	sprintf(packet,"%s��%s",clients[w]->user.nick,msg);
	Broadcast(CHAT_CHANNEL,packet,w);
}
void onChatAll(int w,char *msg){
	char packet[256];
	sprintf(packet,"%s��%s",clients[w]->user.nick,msg);
	Broadcast(CHAT_AREA,packet,w);
}
/*
TODO : ������ �����ϴ� Ŭ���̾�Ʈ���Ը� �޼��� ������
*/
void onTankJoin(int w,char *msg){
	char *_area = msg;

	sprintf(clients[w]->user.area,_area);

	output("%d joined to area %s\n",w, _area);

	__ENTER(csClients);
	/*clients[w]->user.x = 0;
	clients[w]->user.y = 0;
	clients[w]->user.speed = 8;*/
	clients[w]->user.joined = true;
	__ENTER(csArea);
	//game.push_back(clients[w]);
	area[string(_area)].push_back(clients[w]);
	__LEAVE(csArea);

	char msg2[64];
	sprintf(msg2,"%d", w);
	BroadcastArea(_area,TANK_JOIN,msg2,w);
	/*for(int i=0;i<clients.size();i++){
		if(clients[i]->n == w) continue;
		Send(i,TANK_JOIN,msg2);
	}*/
	sprintf(msg2,"%d,%s,%d", w,"nick",VAR_STRING);
	BroadcastArea(_area,VAR_NEW,msg2,w);
	sprintf(msg2,"%d,%s,%s", w,"nick",clients[w]->user.nick);
	BroadcastArea(_area,VAR_CHANGE,msg2,w);

	sprintf(msg2,"-1,%d,%d", clients[w]->user.x,clients[w]->user.y);
	Send(w,TANK_MOVE,msg2);

	vector<PER_HANDLE_DATA*> &Area = area[string(_area)];
	for(int i=0;i<Area.size();i++){
		if(Area[i]->n == w) continue;
		sprintf(msg2,"%d", Area[i]->n);
		Send(w,TANK_JOIN,msg2);
		sprintf(msg2,"%d,%d,%d", Area[i]->n,Area[i]->user.x,Area[i]->user.y);
		Send(w,TANK_MOVE,msg2);

		SendVarNew(w,Area[i]->n,"nick",VAR_STRING);
		SendVarChange(w,Area[i]->n,"nick",Area[i]->user.nick);
	}
	__LEAVE(csClients);
}
void onTankMove(int w,char *msg){
	char *x,*y;
	x = strtok(msg,",");
	y = strtok(NULL,",");

	output("moved %d\n", w);

	__ENTER(csClients);
	clients[w]->user.x = atoi(x);
	clients[w]->user.y = atoi(y);
	__LEAVE(csClients);

	char msg2[16];
	sprintf(msg2,"%d,%s,%s", w,x,y);
	BroadcastArea(clients[w]->user.area,
				TANK_MOVE,msg2,w);
	output("broadcasted %d\n", w);
	/*for(int i=0;i<clients.size();i++){
		if(clients[i]->n == w) continue;
		Send(i,TANK_MOVE,msg2);
	}*/
	
}
void onTankLeave(int w,char *msg){
	char msg2[16];
	sprintf(msg2,"%d", w);

	output("%d left area %s\n",w, clients[w]->user.area);

	__ENTER(csClients);
	clients[w]->user.joined = false;
	__LEAVE(csClients);

	vector<PER_HANDLE_DATA*> &Area =
			area[string(clients[w]->user.area)];

	__ENTER(csArea);
	for(int i=0;i<Area.size();i++){
		if(Area[i]->n == w){
			for(int j=i;j<Area.size()-1;j++)
				Area[j] = Area[j+1];
			Area.pop_back();
			break;
		}
	}
	__LEAVE(csArea);

	BroadcastArea(clients[w]->user.area,
				TANK_LEAVE,msg2,w);
	//__ENTER(csClients);
	/*for(int i=0;i<clients.size();i++){
		if(clients[i]->n == w) continue;
		Send(i,TANK_LEAVE,msg2);
	}*/
	//__LEAVE(csClients);
}

/*
�� Ŭ���̾�Ʈ�� ������ �����Ǿ��� ��
false�� �����ϸ� ���� �ź�.
*/
bool onConnect(int w,char *ip){
	
	// �� ��Ͽ� �ִ� ���������� �����Ѵ�.
	if(isBlockedIP(ip))
		return false;

	return true;
}

/*
Ŭ���̾�Ʈ���� ������ �������� ��
*/
void onDisconnect(int w,char *ip){
	char *id = clients[w]->user.id;
	output("%s logged out\n", id);

	if(isSessionOpened(id)){
		output("close session %d\n", session[string(id)]);

		Database *db;
		db = clients[w]->user.db;

		db->set("x",
				(void*)&clients[w]->user.x,
				sizeof(int));
		db->set("y",
				(void*)&clients[w]->user.y,
				sizeof(int));
		db->save();
		db->close();

		if(clients[w]->user.joined)
			onTankLeave(w,"");

		map<string, int>::iterator  itor;

		__ENTER(csSession);
		itor = session.find(string(id));
		session.erase(itor);
		__LEAVE(csSession);
	}
}

/*
Ŭ���̾�Ʈ�� �α����� ��û�� ��
*/
void onLogin(int w,char *msg){
	char *id,*pw;
	id = strtok(msg,",");
	pw = strtok(NULL,",");
	
	// ������ �̹� ����
	if(isSessionOpened(id)){
		output("%s already logged in..\n",id);
		Send(w,LOGIN_SESSION_EXIST,"already logged in");
		return;
	}

	char path[256];
	sprintf(path,"accounts\\%s", id);
	FILE *fp = fopen(path,"r");

	// �����ϴ� ���� ������ ���� ���
	if(fp == NULL){
		Send(w,LOGIN_DENY,"out");
		return;
	}

	output("login - %s\n", id);

	char rpw[128];
	fread(rpw,sizeof(char),128,fp);
	fread(
		clients[w]->user.nick,sizeof(char),32,fp);

	// ��й�ȣ�� ��ġ���� ���� ��
	if(strcmp(rpw,pw)){
		Send(w,LOGIN_DENY,"wp");
		return;
	}

	sprintf(clients[w]->user.id,id);

	fclose(fp);


	// ������ �����Ѵ�.
	__ENTER(csSession);
	session[string(id)] = w;
	__LEAVE(csSession);

	// �ش� ������ db�� ����
	Database *db;
	sprintf(path,"accounts\\%s.db",id);
	db = Database::create(path);
	clients[w]->user.db = db;
	// �ֱ� ��ǥ���� ���´�.
	clients[w]->user.x = *(int *)db->get("x");
	clients[w]->user.y = *(int *)db->get("y");

	// �α��� �Ϸ� ��ȣ�� ������.
	Send(w,LOGIN_ACCEPT,clients[w]->user.nick);

	// ������ ������ ������ �����Ѵ�.
	sprintf(path,"accounts\\%s.png",id);
	SendFile(w,path);
}
/*
Ŭ���̾�Ʈ�� ȸ�� ������ ��û�� ��
*/
void onSignup(int w,char *msg){
	char *id,*pw,*nick;
	id = strtok(msg,",");
	pw = strtok(NULL,",");
	nick = strtok(NULL,",");

	char path[256];
	sprintf(path,"accounts\\%s", id);
	FILE*fp = fopen(path,"r");
	// �̹� �����ϴ� ���̵��� ���
	if(fp != NULL){
		Send(w,SIGNUP_ERR_ID,"exist");
		fclose(fp);
		return;
	}
	fp = fopen(path,"w");
	// � ������ ������ ������ �� ���� ���
	if(fp == NULL){
		output("failed to create account\n");
		Send(w,SIGNUP_ERR_ID,"err");
		return;
	}

	output("new account : %s/%s\n", id,nick);

	// ���� ���� �Է�
	char wpw[128];
	char wnick[32];
	sprintf(wpw,pw);
	sprintf(wnick,nick);
	fwrite(wpw,sizeof(char),128,fp);
	fwrite(wnick,sizeof(char),32,fp);
	fclose(fp);

	// ������ ������ �����Ѵ�
	sprintf(path,"accounts\\%s.png",id);
	FILE *fpSrc = fopen("resource\\profile.png","rb");
	FILE *fpDst = fopen(path,"wb");
	char d;
	if(fpSrc == NULL || fpDst == NULL){
		if(fpSrc != NULL) fclose(fpSrc);
		if(fpDst != NULL) fclose(fpDst);

		output("failed to copy profile image\n");
		Send(w,SIGNUP_ERR_UNKNOWN,"pi");
		return;
	}
	while(1){
		if(feof(fpSrc)){
			break;
		}
		char c = fgetc(fpSrc);
		fputc(c,fpDst);
	}
	fclose(fpSrc);
	fclose(fpDst);

	// �Ϸ��� �޼��� ����
	Send(w,SIGNUP_OK,"logged in");
}
void onPing(int w,char *msg){
	int ts = atoi(msg);
	char msg2[8] = {'\0'};

	output("ping reply from %d / %dms\n", w, GetTickCount64()-ts);

	clients[w]->ping = GetTickCount64()-ts;
	sprintf(msg2,"%d", clients[w]->ping);

	Send(w,PING_NOTIFY,msg2);
}

void onVarNew(int w,char *msg){
	LPVAR var;
	unsigned char type;

	type = atoi(msg);

	var = new VAR;
	var->type = type;

	memset(var,0,sizeof(VAR));

	clients[w]->user.var[string(msg)] = var;
}
void onVarDelete(int w,char *msg){
	LPVAR var;

	var = clients[w]->user.var[string(msg)];

	// ��Ʈ�� Ÿ���� �����̸�
	if(var->type == VAR_STRING)
		// ���ڿ����� ���� ����
		delete var->data.s;

	delete var;
}
void onVarChange(int w,char *msg){
	LPVAR var;

	var = clients[w]->user.var[string(msg)];

	switch(var->type){
		case VAR_INT:
			{
				var->data.i = atoi(msg);
			}
			break;
		case VAR_FLOAT:
			{
				var->data.f = atof(msg);
			}
			break;
		case VAR_CHAR:
			{
				var->data.c = msg[0];
			}
			break;
		case VAR_STRING:
			{
				int len;

				len = strlen(msg);

				// ���� ����� ���ڿ� ���̸�ŭ ���Ҵ�
				var->data.s = (char*)realloc(var->data.s,
					sizeof(char) * len);

				memcpy(var->data.s,msg,sizeof(char) * len);
			}
			break;
	}
}

/*
������ �ʱ�ȭ�Ѵ�.
*/
void Initialize(){

	LoadBlacklist();
	StartWeblog();
	StartPingUpdate();

	InitializeCriticalSection(&csSession);
	InitializeCriticalSection(&csClients);
	InitializeCriticalSection(&csArea);

	RegistHandler(LOGIN,onLogin);
	RegistHandler(SIGNUP,onSignup);

	RegistHandler(TANK_JOIN,onTankJoin);
	RegistHandler(TANK_MOVE,onTankMove);
	RegistHandler(TANK_LEAVE,onTankLeave);

	RegistHandler(VAR_NEW,onVarNew);
	RegistHandler(VAR_CHANGE,onVarChange);
	RegistHandler(VAR_DELETE,onVarDelete);

	RegistHandler(CHAT_AREA,onChatArea);
	RegistHandler(CHAT_CHANNEL,onChatChannel);
	RegistHandler(CHAT_ALL,onChatAll);

	RegistHandler(PING,onPing);

	uptime_st = GetTickCount64();
	ping_update_st = GetTickCount64();

	//area[string("main")].push_back(NULL);
}
/*
������ �����Ѵ�.
*/
void Quit(){
	DeleteCriticalSection(&csSession);
	DeleteCriticalSection(&csClients);
	DeleteCriticalSection(&csArea);

	UnloadBlacklist();
	StopWeblog();
	StopPingUpdate();
}


int main(int argc, char** argv)
{
	WSADATA wsaData;
	HANDLE hCompletionPort;      
	SYSTEM_INFO SystemInfo;
	SOCKADDR_IN servAddr;
	LPPER_IO_DATA PerIoData;
	LPPER_HANDLE_DATA PerHandleData;

	SOCKET hServSock;
	DWORD RecvBytes;
	int i;
	DWORD Flags;

	SetConsoleTitleA("TankOnline Server");

	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		output("startup error\n");

	DWORD dwProcessor;

	GetSystemInfo(&SystemInfo);

	dwProcessor = SystemInfo.dwNumberOfProcessors;

	hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, (dwProcessor * 2));

	for(i=0; i < (dwProcessor * 2); i++) {
		//CreateThread(NULL, 0, CompletionThread, (LPVOID)hCompletionPort, 0, NULL);
		_beginthreadex(NULL, 0, CompletionThread, (LPVOID)hCompletionPort, 0, NULL);
	}

	hServSock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	servAddr.sin_family=AF_INET;
	servAddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servAddr.sin_port=htons(SERVER_PORT);


	if(bind(hServSock, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
		output("bind error\n");
		return 1;
	}

	if(listen(hServSock, 5) == SOCKET_ERROR) {
		output("listen error\n");
		return 1;
	}

	output("server ready - %dcore/%dthread\n",dwProcessor,dwProcessor*2);


	// ���α׷� �ʱ�ȭ
	Initialize();

	// ���� ��Ʈ�ѷ� �����带 ����
	_beginthreadex(NULL, 0, ControlThread, NULL, 0, NULL);

	int N = 0;
	do
	{      
		SOCKET hClntSock;
		SOCKADDR_IN clntAddr;        
		int addrLen=sizeof(clntAddr);
		bool ret;

		// �� Ŭ���̾�Ʈ ������ �����Ѵ�.
		hClntSock=accept(hServSock, (SOCKADDR*)&clntAddr, &addrLen);  

		char t = TRUE;
		setsockopt(hClntSock, IPPROTO_TCP, TCP_NODELAY, &t, sizeof(t));

		output("connected... %s - %d\n", inet_ntoa(clntAddr.sin_addr),N);

		// onConnect �ڵ鷯�� ȣ���Ѵ�.
		ret = onConnect(N,inet_ntoa(clntAddr.sin_addr));
		if(ret == false){
			// ���� �źε�
			output("connection denied\n");
			continue;
		}

		PerHandleData=(LPPER_HANDLE_DATA)malloc(sizeof(PER_HANDLE_DATA));          
		PerHandleData->hClntSock=hClntSock;
		PerHandleData->n = N;
		PerHandleData->fileRecv = false;
		memset(&PerHandleData->user,0,sizeof(USER_DATA));
		memcpy(&(PerHandleData->clntAddr), &clntAddr, addrLen);

		CreateIoCompletionPort((HANDLE)hClntSock,hCompletionPort,(DWORD)PerHandleData,0);

		PerIoData = (LPPER_IO_DATA)malloc(sizeof(PER_IO_DATA));
		memset(&(PerIoData->overlapped), 0, sizeof(OVERLAPPED));           
		PerIoData->wsaBuf.len = BUFSIZE;
		PerIoData->wsaBuf.buf = PerIoData->buffer;
		Flags=0;

		clients[N] = PerHandleData;

		WSARecv(PerHandleData->hClntSock,
			&(PerIoData->wsaBuf),
			1,                
			&RecvBytes,                                 
			&Flags,
			&(PerIoData->overlapped),
			NULL
			);        
	}while(++N);

	WSACleanup();
	Quit();

	return 0;
}

void ControlShell(){
	output("--ControlShell\n");
	while(1){
		char line[256];
		char *cmd;

		output("<< ");
		gets(line);

		cmd = strtok(line," ");
		
		if(!strcmp(cmd,"exit")){
			output(">> exit control shell\n");
			break;
		}
		else if(!strcmp(cmd,"builddate")){
			output(">> %s\n", __DATE__);
		}
		else if(!strcmp(cmd,"clear")){
			char *p1;
			p1 = strtok(NULL," ");

			if(!strcmp(p1,"log")){
				ClearLog();
			}
			else if(!strcmp(p1,"blacklist")){
				ClearBlacklist();
			}
		}
		else if(!strcmp(cmd,"reload")){
			char *p1;
			p1 = strtok(NULL," ");

			if(!strcmp(p1,"blacklist")){
				UnloadBlacklist();
				LoadBlacklist();
				output(">> blacklist reloaded\n");
			}
		}
		else if(!strcmp(cmd,"list")){
			char *p1;
			p1 = strtok(NULL," ");

			if(!strcmp(p1,"connection")){
				map<int,PER_HANDLE_DATA*>::iterator itor;
			
				output(">> connection list\n");
				for(itor=clients.begin();itor!=clients.end();++itor){
					output(">>   %d - %s\n", 
						itor->first,inet_ntoa(itor->second->clntAddr.sin_addr));
				}
				output("\n");
			}
			else if(!strcmp(p1,"blacklist")){
				EnumBlacklist();
			}
		}
		else if(!strcmp(cmd,"uptime")){
			char *p1;
			p1 = strtok(NULL," ");

			if(p1 == NULL){
				unsigned long tick = GetTickCount64();
				tick = tick - uptime_st;
				tick /= 1000;
				printf("%d\n", tick);
				output(">> server uptime : %dday %dhour %dminute %dsecond\n",
							tick / 60 / 60 / 24,
							tick % (3600 * 24) / 60 / 60,
							tick % 3600 / 60,
							tick % 60);
			}
			else if(!strcmp(p1,"system")){
				unsigned long tick = GetTickCount64();
				tick /= 1000;
				output(">> system uptime : %dday %dhour %dminute %dsecond\n",
							tick / 60 / 60 / 24,
							tick % (3600 * 24) / 60 / 60,
							tick % 3600 / 60,
							tick % 60);
			}
			
		}
	}
}
unsigned int __stdcall ControlThread(void *arg){
	output("Server ControlPanel Ready\n");
	while(1){
		int ch;
		ch = _getch();

		switch(ch){
		case 'b':
			{
				char msg[256];

				output("message : ");
				gets(msg);

				Broadcast(CHAT_SYSTEM,msg);
			}
			break;
		case 'i':
			{
				output("TankOnline Server, %s\n", __DATE__);
			}
			break;
		case 's':
			{
				ControlShell();
			}
			break;
		case 'q':
			{
				exit(0);
			}
			break;
		case 'p':
			{
				char t[32];
				sprintf(t,"%d", GetTickCount64());
				Broadcast(PING,t);
			}
			break;
		}
	}
}
unsigned int __stdcall CompletionThread(void* pComPort)
{
	HANDLE hCompletionPort =(HANDLE)pComPort;
	DWORD BytesTransferred;

	LPPER_HANDLE_DATA      PerHandleData;
	LPPER_IO_DATA          PerIoData;

	DWORD flags;

	while(1)
	{
		GetQueuedCompletionStatus(hCompletionPort,
			&BytesTransferred,
			(LPDWORD)&PerHandleData,
			(LPOVERLAPPED*)&PerIoData,
			INFINITE);

		// 0 ����Ʈ ������ -> ���� �����
		if(BytesTransferred == 0)
		{
			output("closed %d\n",PerHandleData->n);

			onDisconnect(
				PerHandleData->n,
				inet_ntoa(PerHandleData->clntAddr.sin_addr)
				);

			__ENTER(csClients);
			/*for(int i=0;i<clients.size();i++){
			if(clients[i] == PerHandleData){
			for(int j=i;j<clients.size()-1;j++)
			clients[j] = clients[j+1];
			clients.pop_back();
			break;
			}
			}*/
			map<int,PER_HANDLE_DATA*>::iterator itor;
			itor = clients.find(PerHandleData->n);
			clients.erase(itor);
			__LEAVE(csClients);

			closesocket(PerHandleData->hClntSock);
			free(PerHandleData);
			free(PerIoData);
			continue;             
		}             
		PerIoData->wsaBuf.len = BytesTransferred;
		PerIoData->wsaBuf.buf[BytesTransferred] = '\0';

		ParsePacket(PerHandleData->n,
			PerIoData->wsaBuf.buf,
			PerIoData->wsaBuf.len);

		memset(&(PerIoData->overlapped), 0, sizeof(OVERLAPPED));
		PerIoData->wsaBuf.len=BUFSIZE;
		PerIoData->wsaBuf.buf=PerIoData->buffer;

		flags=0;
		WSARecv(PerHandleData->hClntSock,
			&(PerIoData->wsaBuf),
			1,
			NULL,
			&flags,
			&(PerIoData->overlapped),
			NULL
			);      

	}
	return 0;
}

void SendVarNew(int w,int t,char *name,int type){
	char msg2[64];
	sprintf(msg2,"%d,%s,%d", t,name,type);
	Send(w,VAR_NEW,msg2);
}
void SendVarDelete(int w,int t,char *name){
	char msg2[64];
	sprintf(msg2,"%d,%s", t,name);
	Send(w,VAR_DELETE,msg2);
}
void SendVarChange(int w,int t,char *name,int v){
	char msg2[64];
	sprintf(msg2,"%d,%s,%d", t,name,v);
	Send(w,VAR_CHANGE,msg2);
}
void SendVarChange(int w,int t,char *name,float v){
	char msg2[64];
	sprintf(msg2,"%d,%s,%f", t,name,v);
	Send(w,VAR_CHANGE,msg2);
}
void SendVarChange(int w,int t,char *name,char v){
	char msg2[64];
	sprintf(msg2,"%d,%s,%c", t,name,v);
	Send(w,VAR_CHANGE,msg2);
}
void SendVarChange(int w,int t,char *name,char *v){
	char msg2[64];
	sprintf(msg2,"%d,%s,%s", t,name,v);
	output("%s\n", msg2);
	Send(w,VAR_CHANGE,msg2);
}

void Send(int w,int p,char *msg){
	char packet[1024];
	sprintf(packet,"%d:%s\r\n",
							p,msg);
	DWORD sent;
	WSABUF buf;
	buf.buf = packet;
	buf.len = strlen(packet);
	WSASend(clients[w]->hClntSock,&buf,1,&sent,0,NULL,NULL);
}
void SendBinary(int w,int p,char *data,int len){
	char *packet;
	packet = (char *)malloc(sizeof(char) * len + 7);
	sprintf(packet,"%d:%s\r\n",
							p,data);
	DWORD sent;
	WSABUF buf;
	buf.buf = packet;
	buf.len = len + 6;
	WSASend(clients[w]->hClntSock,&buf,1,&sent,0,NULL,NULL);
}
void SendFile(int w,char *file){
	//FILE *fp = fopen(file,"rb");
	HANDLE fp = CreateFileA(
						file,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						0,
						NULL);
	char msg[32];

	if(fp == INVALID_HANDLE_VALUE){
		output("failed to send file\n");
		Send(w,FILE_ERR,"error");
		return;
	}
	sprintf(msg,"%d", GetFileSize(fp,NULL));
	Send(w,FILE_LENGTH,msg);
	for(int i=strlen(file);i>=0;i--){
		if(file[i] == '\\'){
			sprintf(msg,"%s", file+i+1);
			output("send file %s\n", msg);
			Send(w,FILE_NAME,msg);
			break;
		}
	}
	while(1){
		char buffer[128];
		DWORD dwRead;
		int sent;

		ReadFile(fp,buffer,128,&dwRead,NULL);
		sent = send(clients[w]->hClntSock,buffer,dwRead,0);

		if(sent == -1){
			printf("send failed - %s\n", file);
//			printf("send aborted %s\n", fileName);
			break;
		}
		if(dwRead != 128)
			break;
	}

	CloseHandle(fp);
}

void ParsePacket(int w,char *msg,int msgLength){
	int read;
	vector<char *> token;
	token.push_back(strtok(msg,"\r\n"));

	// ���� �������̸�
	if(clients[w]->fileRecv == true){
		// ���� ��� �� ���� ���� ���� ��Ŷ���� Ŭ ��
		if((clients[w]->fileLength - clients[w]->fileWritten) > msgLength){
			fwrite(msg,sizeof(char),msgLength,clients[w]->filePointer);
			clients[w]->fileWritten += msgLength;
			return;
		}
		// ���� ��� �� ���� ���� ���� ��Ŷ���� ���� -> ������ŭ ���� ������ �Ľ�
		else{
			fwrite(msg,sizeof(char),
					clients[w]->fileLength - clients[w]->fileWritten,
					clients[w]->filePointer);
			fclose(clients[w]->filePointer);
			msg = msg + clients[w]->fileLength - clients[w]->fileWritten;
			clients[w]->fileRecv = false;
			clients[w]->fileReceived = true;

			if(clients[w]->fileLength - clients[w]->fileWritten == msgLength)
				return;
		}
	}

	// 1�� �Ľ�
	//   \r\n�� �������� ��Ŷ�� ������.
	char msg2[1024];
	memcpy(msg2,msg,sizeof(char) * msgLength);
	while(1){
		char *tok;
		tok = strtok(NULL,"\r\n");
		if(tok != NULL){
			token.push_back(tok);
		}
		else break;
	}

	// 2�� �Ľ�
	//   �ڵ��ȣ�� �޼����� ������.
	read = 0;
	for(int i=0;i<token.size();i++){
		int code;
		char *msg = NULL;
		for(int j=0;j<strlen(token[i]);j++){
			if(token[i][j] == ':'){
				token[i][j] = '\n';
				code = atoi(token[i]);
				msg = token[i] + j+1;
				break;
			}
		}
		read += strlen(token[i]) + 2;

		// ���� ���̸� ���۹޾��� ��
		if(code == FILE_LENGTH){
			clients[w]->fileLength = atoi(msg);
			output("file length : %d\n", clients[w]->fileLength);
		}
		// ���� �̸��� ���۹޾��� �� -> ���� ������ �����Ѵ�.
		else if(code == FILE_NAME){
			sprintf(clients[w]->fileName,msg);
			output("file name : %s\n", clients[w]->fileName);

			clients[w]->filePointer = fopen(clients[w]->fileName,"wb");
			if(clients[w]->filePointer == NULL){
				output("failed to create file\n");
			}
			clients[w]->fileWritten = 0;
			clients[w]->fileRecv = true;

			if(i != token.size()-1){
				ParsePacket(w,msg2+read,msgLength-read);
				break;
			}
			break;
		}

		if(handler[code].handler != NULL){
			handler[code].handler(w,msg);
		}
	}
}
void RegistHandler(int code,void (*cb)(int,char *)){
	handler[code].handler = cb;
}