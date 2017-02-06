#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "../inc/poolsocket.h"
#include "../inc/keymngserverop.h"
#include "../inc/keymnglog.h"

MngServer_Info 			mngServerInfo;
int  g_tagEnd = 0;

void *(mystart_routine) (void *arg)
 {
 	int 			ret = 0;
 	int 			timeout = 3;
 	
 	int connfd = (int)arg;
 	
 	//客户端请求信息	
 	MsgKey_Req		*pMsgKeyReq = NULL;
 	int 			iMsgKeyReqType = 0;
 				
 	//应答报文 编码以后的结果
 	unsigned char 	*pMsgKeyResData = NULL; 
 	int 			iMsgKeyResDataLen = 0;
 	
 	while (1)
 	{
 		if (g_tagEnd == 1)
 		{
 			break;
 		}
 		 unsigned char 		*out = NULL;
 		 int 				outlen = 0;
 	
 		pMsgKeyResData = NULL;
 		iMsgKeyResDataLen = 0;
 		//服务器端端接受报文
 		ret = sckServer_rev(connfd, timeout, &out, &outlen); //1
 		if (ret == Sck_ErrPeerClosed)
 		{ 
 			printf("sckServer_rev 服务器端检查到客户端已经关闭 所以服务器端链接需要关闭\n");
 			break;	
 		}
 		else if (ret == Sck_ErrTimeOut)
 		{
 			printf(" sckServer_rev timeout \n");
 			continue;
 		}
 		else if (ret != 0)
 		{
 			printf("fun sckServer_rev() err:%d \n", ret);
 			break;
 		}
 		
 		//解析客户端的请求报文
 		ret = MsgDecode(out, outlen,  (void **)&pMsgKeyReq, &iMsgKeyReqType);
 		if (ret != 0)
 		{
 			sck_FreeMem((void **)&out);
 			printf("func MsgDecode() err:%d \n", ret);
 			continue;
 		}
 
 		//根据请求报文的命令码 做不同的动作
 		switch (pMsgKeyReq->cmdType)
 		{
 		case KeyMng_NEWorUPDATE:
 			//相应业务流api函数()  
 			ret = MngServer_Agree(&mngServerInfo, pMsgKeyReq, (unsigned char**)&pMsgKeyResData, &iMsgKeyResDataLen);
 			 if(ret != 0)
 			 {
 			 		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngServer_Agree() err");
 			 }
 			break;
 		case KeyMng_Check:
 			//相应业务流api函数
 			 ret = MngServer_Check(&mngServerInfo,pMsgKeyReq,(unsigned char**)&pMsgKeyResData, &iMsgKeyResDataLen);
 			 if(ret != 0)
 			 {
 			 		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngServer_Check() err");
 			 }
 			break;
 		case KeyMng_Revoke:
 			//相应业务流api函数
 			break;
 		default :
 			ret = KeyMng_ParamErr;
 			printf("check pMsgKeyReq->cmdType:%d  err\n", pMsgKeyReq->cmdType);
 			break;			
 		}
 		
 		if (ret != 0)
 		{
 			printf("服务器应答业务流失败 err:%d \n", ret);
 		}
 		
 		//服务器端发送报文
		ret = sckServer_send(connfd, 3, (void *)pMsgKeyResData, iMsgKeyResDataLen);
		if (ret == Sck_ErrPeerClosed)
 		{
 			MsgMemFree((void **)&pMsgKeyResData, 0); //释放 应答报文的 der编码结果
 			sck_FreeMem((void **)&out);
 			MsgMemFree((void **) &pMsgKeyReq, iMsgKeyReqType); //释放客户端请求报文结构体
 			printf(" sckServer_send 服务器端检查到客户端已经关闭 所以服务器端链接需要关闭\n");
 			break;	
 		}
 		else if (ret == Sck_ErrTimeOut)
 		{
 			MsgMemFree( (void **) &pMsgKeyResData, 0); //释放 应答报文的 der编码结果
 			sck_FreeMem((void **)&out);
 			MsgMemFree( (void **) &pMsgKeyReq, iMsgKeyReqType); //释放客户端请求报文结构体
 			printf("sckServer_send timeout \n");
 			continue;
 		}
 		else if (ret != 0)
 		{
 			sck_FreeMem((void **)&out);
 			MsgMemFree( (void **) &pMsgKeyResData, 0); //释放 应答报文的 der编码结果
 			MsgMemFree( (void **) &pMsgKeyReq, iMsgKeyReqType); //释放客户端请求报文结构体
 			printf("fun sckServer_send() err:%d \n", ret);
 			break;
 		}
 		sck_FreeMem((void **)&out);
 		MsgMemFree( (void **) &pMsgKeyResData, 0); //释放 应答报文的 der编码结果
 		MsgMemFree( (void **) &pMsgKeyReq, iMsgKeyReqType); //释放客户端请求报文结构体
 	}

	//当客户端已经关闭的时候,服务器才有权利把链接关掉
	sckServer_close(connfd);
 	return NULL;
 }
       
#define INIT_DAEMON \
{ \
	if(fork() >0) exit(0); \
	setsid(); \
	if(fork()>0) exit(0); \
}

void mysighandler_t(int arg)
{
	printf("守护进程收到信号,进行退出操作arg:%d \n", arg);
	g_tagEnd  = 1;
}

int main()
{
	int					ret = 0;
	int 				timeout = 3;
	int 				listenfd = 0;
	int 				connfd = 0;
	
	g_tagEnd = 0;
	pthread_t 			pid = 0;
	
	//注册信号 
	signal(SIGUSR1, mysighandler_t);
	
	signal(SIGPIPE, SIG_IGN); 
	
	memset(&mngServerInfo, 0, sizeof(MngServer_Info));
	
	INIT_DAEMON 
	//keymngserver初始化
	// serverid shmid maxnodenum (最大网点个数) ip port 
	// 链接数据库的配置信息
	// user userpd sid
	ret =  MngServer_InitInfo(&mngServerInfo);
	if (ret != 0)
	{
		printf("func MngServer_InitInfo() err :%d \n", ret);
		return ret;
	}
		
	//服务器端初始化
	ret = sckServer_init(8001, &listenfd);
	if (ret != 0)
	{
		printf("func  sckServer_init() err:%d \n", ret);
		return ret;
	}

	while (1)
	{
		if (g_tagEnd == 1)
		{
			break;
		}
		ret = sckServer_accept(listenfd, timeout, &connfd);
		if (ret == Sck_ErrTimeOut)
		{
			printf("info: sckServer_accept() timeout \n");
			continue; 
		}
		else if (ret != 0)
		{
			;
		}
		//创建服务线程
		pthread_create(&pid, NULL,   mystart_routine, (void* )connfd);
	}
	
	sleep(1);
	
	//服务器端环境释放 
	sckServer_destroy();

	printf("主进程优雅退出...\n");
	
	return 0;	
}
