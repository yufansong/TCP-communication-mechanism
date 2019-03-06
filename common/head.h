#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <sys/shm.h>
/*--------------------------宏定义-----------------------------------*/
#define MAX_CONFIG 20
#define MAX_LENGTH 128
#define MAX_ETHERNET_LENGTH 14
#define MAX_IP_LENGTH 20
#define MAX_TCP_LENGTH 20
/*  ???
物理层 0字节
数据链路层 Ethernet头(14字节)
网络层 20字节ip头
传输层 20字节tcp头
应用层 20字节数据
*/
#define W_FILE_NAME_0 "receiver.dat"
#define W_FILE_NAME_1 "sender.dat"
#define W_FILE_NAME_2 "network.dat"
#define W_FILE_NAME_3 "tcp.dat"
#define W_FILE_NAME_4 "ip.dat"
#define R_FILE_NAME "../common/network.conf"

//读取配置文件
#define SUCCESS 0x00 /*成功*/
#define FAILURE 0x01 /*失败*/

#define FILENAME_NOTEXIST 0x02    /*配置文件名不存在*/
#define SECTIONNAME_NOTEXIST 0x03 /*节名不存在*/
#define KEYNAME_NOTEXIST 0x04     /*键名不存在*/
#define STRING_LENNOTEQUAL 0x05   /*两个字符串长度不同*/
#define STRING_NOTEQUAL 0x06      /*两个字符串内容不相同*/
#define STRING_EQUAL 0x00         /*两个字符串内容相同*/

struct _Ether_pkg
{
    /* 前面是ethernet头 */
    unsigned char ether_dhost[6];  /* 目地硬件地址 */
    unsigned char ether_shost[6];  /* 源硬件地址 */
    unsigned short int ether_type; /* 网络类型 */
};

/*--------------------------sender函数-----------------------------------*/
int send_application(char *buf);
void send_transport(char *buf);
void send_network(char *buf);
void send_datalink(char *buf);
void send_physics(char *buf);

/*--------------------------reciever函数-----------------------------------*/
void recieve_application(unsigned char *buf, int data_len);
void recieve_transport(unsigned char *buf);
int recieve_network(unsigned char *buf);
void recieve_datalink(unsigned char *buf);
void recieve_physics(unsigned char *buf);

/*--------------------------随机+写文件函数-----------------------------------*/
void get_random_byte(char *buf, int length); //每次读取一个字节的随机填充字节
void write_file(char *str_write, const char *file_name,int length);
unsigned char str_to_hex(const char *str);

/*--------------------------获得配置文件函数-----------------------------------*/
int get_config_str(char *SectionName, char *KeyName, char *str); //传进去的str是需要读取的字符串
int get_config_int(char *SectionName, char *KeyName);            //返回值是读取的int8
int CompareString(char *pInStr1, char *pInStr2);
int GetKeyValue(FILE *fpConfig, char *pInKeyName, char *pOutKeyValue);
int GetConfigIntValue(char *pInFileName, char *pInSectionName, char *pInKeyName, int *pOutKeyValue);
int GetConfigStringValue(char *pInFileName, char *pInSectionName, char *pInKeyName, char *pOutKeyValue);

/*--------------------------tcp函数-----------------------------------*/
int creator_tcphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
                      struct sockaddr_in *dst_addr, int len_total);
int creator_header_tcp(struct tcphdr *header_tcp);
unsigned short creator_check_sum(const char *buf, int protocol);

int creator_tcp(void);