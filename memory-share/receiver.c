#include "../common/head.h"
int main(int argc, char const *argv[])
{
/*------------------------share memory---------------------------*/
    void *shm = NULL;
    char *buf; // 指向shm
    int shmid;                    // 共享内存标识符
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
    for (i = 0; i < MAX_LENGTH; i++)
        buf[i] = 0;
    char *buf_temp;

    if (fork() == 0)
    {
        recieve_physics(buf);
        if (fork() == 0)
        {
            recieve_datalink(buf);
            if (fork() == 0)
            {
                buf_temp = buf + MAX_ETHERNET_LENGTH;
                int data_len = recieve_network(buf_temp);
                data_len -= MAX_IP_LENGTH;
                data_len -= MAX_TCP_LENGTH;
                if (fork() == 0)
                {
                    buf_temp = buf + MAX_ETHERNET_LENGTH;
                    recieve_transport(buf_temp);
                    if (fork() == 0)
                    {
                        buf_temp = buf + MAX_ETHERNET_LENGTH + MAX_IP_LENGTH +MAX_TCP_LENGTH;
                        recieve_application(buf_temp,data_len);
                    }
                    return 0;
                }
                return 0;
            }
            return 0;
        }
        return 0;
    }
    
    // //物理层
    // recieve_physics(buf);

    // // //数据链路层
    // recieve_datalink(buf);

    // //网络层
    // buf_temp = buf + MAX_ETHERNET_LENGTH;
    // int data_len = recieve_network(buf_temp);
    // data_len -= MAX_IP_LENGTH;
    // data_len -= MAX_TCP_LENGTH;

    // // //传输层
    // buf_temp = buf + MAX_ETHERNET_LENGTH;
    // recieve_transport(buf_temp);

    // // // 应用层
    // buf_temp = buf + MAX_ETHERNET_LENGTH + MAX_IP_LENGTH +MAX_TCP_LENGTH;
    // recieve_application(buf_temp,data_len);
    
    return 0;
}
