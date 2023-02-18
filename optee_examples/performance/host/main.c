#include<stdio.h>
#include<stdlib.h>
#include<time.h>
int main()
{
	struct timespec start = {0,0};
	struct timespec end = {0,0};
	char * buffer;
	double duration = 0;
	char a;
	buffer = (char*) malloc(100*1024*1024);
	for(int i = 0; i < 100*1024*1024; i++)//写100MB内存
	{
		buffer[i] = rand()%100+'a';
	}
	clock_gettime(CLOCK_REALTIME, &start);
	printf("CLOCK_REALTIME: %d, %d\n", start.tv_sec, start.tv_nsec);
	for(int num = 0; num < 10; num++)//10次
	{
		for(int i = 0; i < 100*1024*1024; i++)//读100MB
		{
			a = buffer[i];
		}
		clock_gettime(CLOCK_REALTIME, &end);
		printf("CLOCK_REALTIME: %d, %d\n", end.tv_sec, end.tv_nsec);
		duration = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000;
		printf("num:%d duration:%f",num,duration);//1次
	}
	printf("Result:%f",duration/10);
	free(buffer);
	return 0;
} 
