#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "md5.h"
 
 
static void printf_hexstream(unsigned char *pData, int len, const char* strTag)
{
	int i;
	//char buff[1024 + 2] = { 0 };
	char buff[1024 + 2];
	int ret = 0;
	int pos = 0;
	memset(buff,'\0',1026);
	for (i = 0; i<len&&i<512; i++)
	{
		ret = sprintf(buff + pos, "%0.2x", pData[i]);
		pos += ret;
	}
	if (strTag)
	{
		printf("\r\n%s %s\r\n", strTag, buff);
	}
	else
	{
		printf("ww:%s\n", buff);
	}
	// printf("\r\n%s:%s\r\n",strTag,buff);
}
 
int testFileMD5_2()
{
	unsigned char buff[64];
 
	printf("\r\n--------test file MD5-----------\n");
	if(get_file_md5("D:\\1.txt",buff)==32)
		printf("ffffffff: %s\n", buff);
	printf("buff:%s\n", buff);
	return 0;
}
 
int main(int argc, char *argv[])
{
    testFileMD5_2();
 
	//printf("\r\n");
	//system("PAUSE");
	return 0;
}