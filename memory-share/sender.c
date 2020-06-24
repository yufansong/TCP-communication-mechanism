#include"../common/head.h"
int main(int argc, char const *argv[])
{
/*------------------------share memory---------------------------*/
    void *shm = NULL;
    char *buf; // 指向shm
    int shmid; // 共享内存标识符
    shmid = shmget((key_t)1234, sizeof(MAX_LENGTH), 0666 | IPC_CREAT);
    if (shmid == -1)
    {
        fprintf(stderr, "shmat failed\n");
        exit(EXIT_FAILURE);
    }
    shm = shmat(shmid, (void *)0, 0);
    if (shm == (void *)-1)
    {
        fprintf(stderr, "shmat failed\n");
        exit(EXIT_FAILURE);
    }
    buf = (char *)shm; // 注意：shm有点类似通过 malloc() 获取到的内存，所以这里需要做个 类型强制转换

/*------------------------fork---------------------------*/
    // char *buf = (char *)malloc(MAX_LENGTH);
    int i = 0;
    for(i=0;i<MAX_LENGTH;i++)
        buf[i] = 0;
    char *buf_temp;
    // pid_t pid = 0;
    if(fork()==0)
    {
        // printf("application\n");
        buf_temp = buf + MAX_ETHERNET_LENGTH + MAX_IP_LENGTH +MAX_TCP_LENGTH;
        send_application(buf_temp);
        if(fork()==0)
        {
            // printf("transport\n");
            buf_temp = buf + MAX_ETHERNET_LENGTH;
            send_transport(buf_temp);
            if (fork() == 0)
            {
                // printf("network\n");
                buf_temp = buf + MAX_ETHERNET_LENGTH;
                send_network(buf_temp);
                if (fork() == 0)
                {
                    // printf("datalink\n");
                    send_datalink(buf);
                    if (fork() == 0)
                    {
                        send_physics(buf);
                        // printf("physics end\n");
                    }
                    else
                        ;
                        // printf("datalink end\n");
                    return 0;
                }
                else
                    ;
                    // printf("network end\n");
                return 0;
            }
            else
                ;
                // printf("transport end\n");
            return 0;
        }
        else
            ;
            // printf("application end\n");
        return 0;
    }
    else
        ;
        // printf("end end\n");
    // printf("final end\n");


    //应用层
    // buf_temp = buf + MAX_ETHERNET_LENGTH + MAX_IP_LENGTH +MAX_TCP_LENGTH;
    // send_application(buf_temp);

    // //传输层
    // buf_temp = buf + MAX_ETHERNET_LENGTH;
    // send_transport(buf_temp);

    // //网络层
    // buf_temp = buf + MAX_ETHERNET_LENGTH;
    // send_network(buf_temp);

    // //数据链路层
    // send_datalink(buf);
    
    // //物理层
    // send_physics(buf);
    return 0;
}
/*
Ethernet    https://www.cnblogs.com/qishui/p/5437301.html
            https://my.oschina.net/liusijia/blog/886970
ip  https://blog.csdn.net/Mary19920410/article/details/59035804
tcp	https://blog.csdn.net/a19881029/article/details/29557837
 
8

int main(int argc, char const *argv[])
{
    char *buf = (char*)malloc(20);
    buf[0] = 0x45;
    buf[1] = 0x0;
    buf[2] = 0x0;
    buf[3] = 0x3c;
    buf[4] = 0x0;
    buf[5] = 0x0;
    buf[6] = 0x40;
    buf[7] = 0x0;
    buf[8] = 0x0;
    buf[9] = 0x6;
    buf[10] = 0x0; //
    buf[11] = 0x0; //
    buf[12] = 0xc0;
    buf[13] = 0xa8;
    buf[14] = 0x50;
    buf[15] = 0xe6;
    buf[16] = 0xa;
    buf[17] = 0x3c;
    buf[18] = 0x66;
    buf[19] = 0xfc;
    int ret = creator_check_sum(buf,0);
    printf("%x\n",ret);
    return 0;
}


*/