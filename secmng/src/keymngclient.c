#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <pthread.h>
#include "../inc/keymnglog.h"

#include "../inc/poolsocket.h"
#include "../inc/keymngclientop.h"
#include "../inc/keymng_msg.h"

int Usage()
{
    int nSel = -1;
    
    system("clear");    
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n  /*     1.密钥协商                                            */");
    printf("\n  /*     2.密钥校验                                            */");
    printf("\n  /*     3.密钥注销                                            */");
    printf("\n  /*     4.密钥查看                                            */");
    printf("\n  /*     0.退出系统                                            */");
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n\n  选择:");
    scanf("%d", &nSel);
    while(getchar() != '\n'); //把应用程序io缓冲器的所有的数据 都读走,避免影响下一次 输入
    
    return nSel;
}

int main()
{
	int 				ret = 0;
	int 				nSel = 0;
	
	MngClient_Info		mngClientInfo;
	memset(&mngClientInfo, 0, sizeof(MngClient_Info));

	//系统初始化
	ret = MngClient_InitInfo(&mngClientInfo);
	if (ret != 0)
	{
		printf("func MngClient_InitInfo() err:%d \n ", ret);
	}
	
	while (1)
	{
		nSel = Usage();
		
		switch (nSel)
		{
		case KeyMng_NEWorUPDATE:	
			//密钥协商
			ret =  MngClient_Agree(&mngClientInfo);
			if(ret != 0)
			{
				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngClient_Agree() err");
		  }
			break;
		case KeyMng_Check:	
			//密钥校验
			 ret = MngClient_Check(&mngClientInfo);
			 if(ret != 0)
				{
					KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngClient_Check() err");
		  	}
			break;
		case KeyMng_Revoke:	
			//密钥注销
			break;
		case 0:	
			//密钥协商
			return 0;
		default :
			printf("选项不支持\n");
			break;
		}
		
		if (ret)
		{
			printf("\n!!!!!!!!!!!!!!!!!!!!ERROR!!!!!!!!!!!!!!!!!!!!");
			printf("\n错误码是：%x\n", ret);
		}
		else
		{
			printf("\n!!!!!!!!!!!!!!!!!!!!SUCCESS!!!!!!!!!!!!!!!!!!!!\n");
		}	
		getchar();	
	}
	
	printf("keymngclient hello...\n");
	return 0;
}

