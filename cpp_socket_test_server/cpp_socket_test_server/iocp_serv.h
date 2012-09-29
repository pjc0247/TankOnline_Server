#include <WinSock2.h>
#include <Windows.h>

extern "C" __declspec(dllimport) void BroadCast(char *message);
extern "C" __declspec(dllimport) void Send(int w,char *message);
extern "C" __declspec(dllimport) int GetClientCount();
extern "C" __declspec(dllimport) SOCKET GetSocket(int w);
extern "C" __declspec(dllimport) void SelectPerson(int w);
extern "C" __declspec(dllimport) int GetSelectedPerson();
extern "C" __declspec(dllimport) void RegistHandler(int type,bool (*Handler)(int ,char *));
extern "C" __declspec(dllimport) int Run_IOCP_Server();
extern "C" __declspec(dllimport) void Echo();
extern "C" __declspec(dllimport) void BroadCastEx(char *message,int *array,int n_array,int Ex_or_In);
extern "C" __declspec(dllimport) void BroadCast2(char *message);

#define HANDLER_ON_CONNECT 0
#define HANDLER_ON_DISCONNECT 1

#define BC_EXCLUDE 1
#define BC_INCLUDE 0