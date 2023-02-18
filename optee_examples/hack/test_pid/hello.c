#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){
    while(1){
    printf("testID 正在运行 [pid:%d]! \n", getpid());
    sleep(30);
    }
    return 0;
}
