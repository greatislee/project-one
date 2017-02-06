#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <pthread.h>

#include "../inc/keymnglog.h"
#include "../inc/socketlog.h"
#include "../inc/keymngserverop.h"
#include "../inc/poolsocket.h"
#include "../inc/keymng_msg.h"
#include "../inc/myipc_shm.h"
#include "../inc/keymng_shmop.h"
#include "../inc/icdbapi.h"
#include "../inc/keymng_dbop.h"



int MngServer_InitInfo(MngServer_Info *svrInfo)
{
	int 			ret = 0;
	printf("func MngServer_InitInfo() begin\n");
	strcpy(svrInfo->serverId, "0001");
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");
	svrInfo->dbpoolnum = 20;
	
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 8001;
	svrInfo->maxnode = 10; //服务器支持的最大网点个数
 	svrInfo->shmkey = 0x0001;
	svrInfo->shmhdl = 0;
		
	//初始化共享内存
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0)
	{
		printf("func KeyMng_ShmInit() err:%d 初始化共享内存失败\n", ret);
	}
	
	printf("func MngServer_InitInfo() end\n");
	
	return 0;
}

//服务器端密钥协商 应答流程
//1 组织应答报文
//2 编码应答报文 
//3 协商密钥
//4 写共享内存
//5 网点密钥写数据库

static int myseckeyid = 100;

int MngServer_Agree(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int 				ret = 0, i = 0;
	MsgKey_Res			msgKeyRes;
	
	//
	if (svrInfo==NULL ||  msgkeyReq==NULL || outData==NULL || datalen==NULL)
	{
		ret = MngSvr_ParamErr;
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngServer_Agree() err, (svrInfo==NULL || msgkeyReq==NULL || outData==NULL || datalen==NULL)");
		return ret;
	}
	memset(&msgKeyRes, 0, sizeof(MsgKey_Res));
	msgKeyRes.rv = 0;
	strcpy(msgKeyRes.clientId, msgkeyReq->clientId);
	strcpy(msgKeyRes.serverId, msgkeyReq->serverId);
	
	for (i=0; i<64; i++)
	{
		msgKeyRes.r2[i] = 'a' + 64;
	}
	//memset(&msgKeyRes, 0, sizeof(MsgKey_Res));
	msgKeyRes.seckeyid = myseckeyid ++;
	
	//客户端请求报文的serverid 和 服务器端的serverdi是否相同; 保证业务的规范性
	if (strcmp(msgKeyRes.serverId,svrInfo->serverId) != 0)
	{
		msgKeyRes.rv = 101;
	}
	
	//编码应答报文
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgEncode() msgKeyRes.clientId:%s", msgKeyRes.clientId);
	ret = MsgEncode(&msgKeyRes, ID_MsgKey_Res, outData, datalen);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgEncode() err");
		return ret;
	}
	
	//协商密钥 r1 r2 
	NodeSHMInfo		nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeSHMInfo));

	nodeShmInfo.status =  0;
	strcpy(nodeShmInfo.clientId, msgkeyReq->clientId);
	strcpy(nodeShmInfo.serverId, msgkeyReq->serverId);
	nodeShmInfo.seckeyid = msgKeyRes.seckeyid;
	
	//r1 abcdefg....
	//r2 1234567....
	//密钥规则是:  a1b2c3d4....
	for (i=0; i<64; i++)
	{
		nodeShmInfo.seckey[2*i]	= msgkeyReq->r1[i];
		nodeShmInfo.seckey[2*i + 1]  =  msgKeyRes.r2[i];
	}
	
	//写共享内存
	//1 写网点 找一个空的位置 写入
	//2 写网点信息 若网点信息已经存在 ,则覆盖 
	ret = KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &nodeShmInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func KeyMng_ShmWrite() err");
		goto End;
	}
End:
	
	return ret;
}


int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int ret = 0, i = 0;
	int temkeyid = 0;

	if (svrInfo == NULL || msgkeyReq == NULL || outData == NULL || datalen == NULL)
	{
		ret = MngSvr_ParamErr;
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func MngServer_Agree() err");
		return ret;
	}
	//组织密钥应答报文
	MsgKey_Res *msgKeyRes = (MsgKey_Res *)malloc(sizeof(MsgKey_Res));
	memset(msgKeyRes, 0, sizeof(MsgKey_Res));
	msgKeyRes->rv = 0;
	strcpy(msgKeyRes->clientId, msgkeyReq->clientId);
	strcpy(msgKeyRes->serverId, msgkeyReq->serverId);
	msgKeyRes->seckeyid = temkeyid;

	//编码应答报文
	//协商密钥 r1 r2 
	NodeSHMInfo		nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeSHMInfo));

	//写共享内存
	//2 写网点信息 若网点信息已经存在 ,则覆盖 
    ret = KeyMng_ShmRead(svrInfo->shmhdl, msgkeyReq->clientId, msgkeyReq->serverId, svrInfo->maxnode, &nodeShmInfo);
	if (ret != 0)
	{
		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func KeyMng_ShmRead() err");
		goto End;
	}

    if (strcmp(msgKeyRes->serverId, svrInfo->serverId) != 0) 
    {
        msgKeyRes->rv = 101;
    }

    if (strncmp(msgkeyReq->r1, (const char *)nodeShmInfo.seckey, 32) != 0) {
        printf("%s\n%s\n", msgkeyReq->r1, nodeShmInfo.seckey);
        msgKeyRes->rv = 1;
    }
    printf("req: %s\nshminfo: %s\n", msgkeyReq->r1, nodeShmInfo.seckey);

	ret = MsgEncode((void *)msgKeyRes, ID_MsgKey_Res, outData, datalen);
	if (ret != 0)
	{
		if (msgKeyRes != NULL)
		{
			free(msgKeyRes);
		}

		Socket_Log(__FILE__, __LINE__, SocketLevel[4], ret, "func MsgEncode() err");
		return ret;
	}

End:

	free(msgKeyRes);
	//free(nodeShmInfo);
	return ret;
}
