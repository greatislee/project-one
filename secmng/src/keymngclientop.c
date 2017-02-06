#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <pthread.h>


#include "../inc/keymng_msg.h"
#include "../inc/myipc_shm.h"
#include "../inc/poolsocket.h"
#include "../inc/keymnglog.h"
#include "../inc/keymngclientop.h"
#include "../inc/keymng_shmop.h"  //网点密钥
#include "../inc/socketlog.h"

    

//初始化客户端 全局变量
int MngClient_InitInfo(MngClient_Info *pCltInfo)
{
	int 		ret = 0;
	printf("fun MngClient_InitInfo() begin\n");	
	
	strcpy(pCltInfo->clientId, "1111");
	strcpy(pCltInfo->AuthCode, "1111");
	strcpy(pCltInfo->serverId, "0001");
	strcpy(pCltInfo->serverip, "127.0.0.1");
	pCltInfo->serverport = 8001;
	pCltInfo->maxnode = 30; //最大的网点个数
 	pCltInfo->shmkey = 0x1111;
	pCltInfo->shmhdl = 0;
	printf("初始化ok\n");
	
	//共享内存的初始化
	//分析1 若共享内存已经存在 则使用旧的
	//分析2 若共享内存不存在 则创建		
	ret = KeyMng_ShmInit(pCltInfo->shmkey, pCltInfo->maxnode, &pCltInfo->shmhdl);
	if (ret != 0)
	{
		printf("func KeyMng_ShmInit() err:%d \n", ret);
		return ret;
	}
	
	printf("fun MngClient_InitInfo() end\n");	
	return 0;
}


/*
1 组织请求报文
2 MsgEncode编码请求报文
3 socketapi发送请求报文
4 socketapi接受应答报文
5 MsgDecodeapi 解析应答报文
6 按照规则 产生密钥
7 shmop api写网点密钥到共享内存
*/
int MngClient_Agree(MngClient_Info *pCltInfo)
{
	int 			ret = 0, i=0;
	unsigned char	*outData = NULL ;
	int				outLen = 0;
	MsgKey_Req 		msgKeyReq;
	int 			mytime = 3;
	int 			connfd = 0;
	
	//接受应答报文
	unsigned char	*msgKeyResData = NULL;
	int				msgKeyResDataLen = 0;
	MsgKey_Res		*pMsgKeyRes = NULL;		
	int 			iMsgKeyResTag = 0;
	
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[1], ret,"func MngClient_Agree() begin");
	
	memset(&msgKeyReq, 0, sizeof(MsgKey_Req));
	
	//组织请求报文
	msgKeyReq.cmdType = KeyMng_NEWorUPDATE;
	strcpy(msgKeyReq.clientId, pCltInfo->clientId);
	strcpy(msgKeyReq.AuthCode, pCltInfo->AuthCode);
	strcpy(msgKeyReq.serverId, pCltInfo->serverId);
	//随机数
	for (i=0; i<64; i++)
	{
		msgKeyReq.r1[i] = 'a' + i;
	}
	
	//2 MsgEncode编码请求报文
	ret = MsgEncode(&msgKeyReq, ID_MsgKey_Req, &outData, &outLen);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgEncode() err");
		return ret;
	}
	
	//socketapi发送请求报文
	//客户端 初始化
	ret =  sckClient_init();
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_init() err");
		goto End;
	}
	
	//客户端 连接服务器
	ret = sckClient_connect(pCltInfo->serverip, pCltInfo->serverport, mytime, &connfd);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_connect() err; serverip:%s, serverport:%d",pCltInfo->serverip, pCltInfo-> serverport);
		goto End;
	}

	//客户端 发送报文
	ret = sckClient_send(connfd, mytime, outData, outLen);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_send() err");
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"client 1111111111111");
	

	//客户端 接受报文
	ret = sckClient_rev(connfd, mytime, &msgKeyResData, &msgKeyResDataLen); //1
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_rev() err");
		goto End;
	}
	
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"client 222222");
	
	//解析应答报文
	ret = MsgDecode(msgKeyResData, msgKeyResDataLen, (void **)&pMsgKeyRes, &iMsgKeyResTag);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgDecode() err");
		goto End;
	}
	
	if (pMsgKeyRes->rv == 0)
	{
		printf("服务器处理密钥协商ok \n");	
		printf("seckeyid:%d \n", pMsgKeyRes->seckeyid);
	}
	else
	{
		ret = pMsgKeyRes->rv;
		printf("服务器处理密钥协商err:%d\n", pMsgKeyRes->rv);	
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func 服务器处理密钥协商失败 err");
	}
	
	//协商密钥 r1 r2 
	NodeSHMInfo		nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeSHMInfo));
	nodeShmInfo.status =  0;
	strcpy(nodeShmInfo.clientId, msgKeyReq.clientId);
	strcpy(nodeShmInfo.serverId, msgKeyReq.serverId);
	nodeShmInfo.seckeyid = pMsgKeyRes->seckeyid; 
	
	//r1 abcdefg....
	//r2 1234567....
	//密钥规则是:  a1b2c3d4....
	for (i=0; i<64; i++)
	{
		nodeShmInfo.seckey[2*i]		 = 	msgKeyReq.r1[i];
		nodeShmInfo.seckey[2*i + 1]  =  pMsgKeyRes->r2[i];
	}
	
	//写共享内存
	//1 写网点 找一个空的位置 写入
	//2  写网点信息 若网点信息已经存在 ,则覆盖 
	
	ret = KeyMng_ShmWrite(pCltInfo->shmhdl, pCltInfo->maxnode, &nodeShmInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func KeyMng_ShmWrite() err");
		goto End;
	}
	
End:
	//客户端 关闭和服务端的连接
	if (connfd > 0)
	{
		sckClient_closeconn(connfd);
	}
	if (outData != NULL) //释放请求报文编码 内存块
	{
		MsgMemFree((void **) &outData, 0);
	}
	
	if (msgKeyResData != NULL) //释放socket接受时的内存块
	{
		sck_FreeMem( (void **) &msgKeyResData);
	}
	
	if (pMsgKeyRes != NULL) //释放请求报文编码 结构体内存
	{
		MsgMemFree((void **) &pMsgKeyRes, iMsgKeyResTag);
	}

	//客户端 释放
	sckClient_destroy();
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[1], ret,"func MngClient_Agree() end");
	return ret;
	
}

//密钥校对
int MngClient_Check(MngClient_Info *pCltInfo)
{
		int ret = 0, i = 0;
		unsigned char	*outData = NULL;
		int	outlen = 0;

		//用于通信的文件描述符
		int cfd = 0;
		int mytime = 3;
		
		//读取共享内存
		NodeSHMInfo pNodeInfo;
		memset(&pNodeInfo, 0, sizeof(NodeSHMInfo));
		
		ret = KeyMng_ShmRead(pCltInfo->shmhdl, pCltInfo->clientId, pCltInfo->serverId, pCltInfo->maxnode, &pNodeInfo);
		if(ret != 0)
		{
			Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "KeyMng_ShmRead() err");
			return ret;
		}
		printf("客户端id: %s\n服务器端id: %s\n对称密钥: %s\n对称密钥id: %d\n", pNodeInfo.clientId, pNodeInfo.serverId, pNodeInfo.seckey, pNodeInfo.seckeyid);
		//组织请求的报文
		MsgKey_Req *req = (MsgKey_Req*)malloc(sizeof(MsgKey_Req));
		memset(req, 0, sizeof(MsgKey_Req));

		strncpy(req->r1, pNodeInfo.seckey, 32);
		req->cmdType = KeyMng_Check;
		strcpy(req->clientId, pCltInfo->clientId);
		strcpy(req->AuthCode, pCltInfo->AuthCode);
		strcpy(req->serverId, pCltInfo->serverId);
		
			//对请求报文编码
	ret = MsgEncode((void *)req, ID_MsgKey_Req, &outData, &outlen);
	if (ret != 0)
	{
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func MsgEncode() err");
		return ret;
	}
	//客户端连接服务器
	ret = sckClient_init();
	if (ret != 0)
	{
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func sckClient_init() err");
		goto End;
	}

	sckClient_connect(pCltInfo->serverip, pCltInfo->serverport, mytime, &cfd);
        printf("bbb\n");
	if (ret != 0)
	{
		printf("客户err服务器\n");
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func sckClient_connect() err; serverip:%s, serverport:%d", pCltInfo->serverip, pCltInfo->serverport);
		goto End;
	}

	//发送报文
	sckClient_send(cfd, mytime, outData, outlen);
        printf("ccc\n");
	if (ret != 0)
	{
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func sckClient_send() err");
		goto End;
	}

	//接收报文
	unsigned char* inData = NULL;
	int inlen = 0;
	sckClient_rev(cfd, mytime, &inData, &inlen);
        printf("fff\n");
	if (ret != 0)
	{
		printf("接收错误\n");
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func sckClient_rev() err");
		goto End;
	}

	//应答报文解码
	MsgKey_Res *res = NULL;
	int type = 0;
	MsgDecode(inData, inlen, (void **)&res, &type);
        printf("ggg\n");
        printf("------------==========%d\n", type);
	if (ret != 0)
	{
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func MsgDecode() err");
		goto End;
	}
    printf("----------%d\n", res->rv);

	//判断密钥协商是否成功
	if (res->rv == 0)
	{
		//密钥协商成功
		printf("服务器处理密钥校验ok \n");
		printf("seckeyid:%d \n", res->seckeyid);
	}
	else
	{
		ret = res->rv;
		printf("服务器处理密钥协商err:%d\n", res->rv);
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func 服务器处理密钥协商失败 err");
	}


End:
	if (cfd > 0)
	{
		sckClient_closeconn(cfd);
	}
	if (req != NULL)
	{
		free(req);
		req = NULL;
	}

	if (outData != NULL)
	{
		MsgMemFree((void **)&outData, 0);
	}

	if (inData != NULL)
	{
		sck_FreeMem((void **)&inData);
	}

	if (res != NULL)
	{
		MsgMemFree((void **)&res, type);
	}

	//客户端释放
	printf("客户端释放\n");
	sckClient_destroy();
	Socket_Log(__FILE__, __LINE__, SocketLevel[1], ret, "func MngClient_Agree() end");
	return 0;
}

//密钥注销
int MngClient_Revoke(MngClient_Info *pCltInfo)
{

	return 0;
}

//查看密钥
int MngClient_view(MngClient_Info *pCltInfo)
{

	return 0;
}


//退出客户端
int MngClient_Quit(MngClient_Info *pCltInfo)
{

	return 0;
}
