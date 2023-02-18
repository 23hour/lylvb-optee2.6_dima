#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int cFunc()
{
    int i=0;

    while(1){
        // printf("Hello,ptrace! [pid:%d]! num is %d\n",getpid(),i++);
        sleep(2);
    }
    return 0;
}

int bFunc()
{
    return cFunc();
}

int aFunc()
{
    return bFunc();
}

int main(){
    printf("testID 正在运行 [pid:%d]! \n", getpid());
    return aFunc();
}
