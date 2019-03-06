#include "head.h"
/*--------------------------sender函数-----------------------------------*/
int send_application(char *buf)
{
    int length = get_config_int("application", "datalen");
    // printf("application length:%d\n",length);
    printf("写入的数据文件长度:%d\n", length);

    get_random_byte(buf, length);
    // printf("strlen:%d\n", strlen(buf));
    write_file(buf, W_FILE_NAME_1, length);
    return length;
}
void send_transport(char *buf)
{
    srand(time(NULL)); //生成伪随机数种子
    struct tcphdr *header_tcp;
    header_tcp = (struct tcphdr *)(buf + sizeof(struct ip));
    // printf("sizeof(ip):%d\n", sizeof(struct ip));
    int srcport;
    int dstport;
    char flag_str[7];
    int urg, ack, psh, rst, syn, fin;
    unsigned int ack_num = rand() % 65535;
    unsigned int ack_seq_num = rand() % 65535;
    int data_len = get_config_int("application", "datalen");
    //srcport
    srcport = get_config_int("transport", "srcport");
    //dstport
    dstport = get_config_int("transport", "dstport");
    //flag
    get_config_str("transport", "flag", flag_str);

    urg = flag_str[0] - '0';
    ack = flag_str[1] - '0';
    psh = flag_str[2] - '0';
    rst = flag_str[3] - '0';
    syn = flag_str[4] - '0';
    fin = flag_str[5] - '0';

    /*开始填写TCP数据报 */
    header_tcp->source = htons(srcport); //源端口
    header_tcp->dest = htons(dstport);   //目的端口

    header_tcp->urg = urg;
    header_tcp->ack = ack;
    header_tcp->psh = psh;
    header_tcp->rst = rst;
    header_tcp->syn = syn;
    header_tcp->fin = fin;

    //其他填充，无需配置
    header_tcp->seq = htons(ack_num);         //发送序列号
    header_tcp->ack_seq = htons(ack_seq_num); //确认序号
    header_tcp->doff = 5;                     //数据偏离位置即data off,其实就是header_tcp报头长度，
    header_tcp->res1 = 0;
    header_tcp->res2 = 0;
    header_tcp->window = htons(100);
    header_tcp->check = 0;
    header_tcp->urg_ptr = 0;

    //tcp校验和
    header_tcp->check = creator_check_sum(buf, IPPROTO_TCP);

    write_file((char *)(header_tcp), W_FILE_NAME_3, MAX_TCP_LENGTH);

    printf("TCP包头基本信息:\n");
    printf("%10s=%d\n", "sport", srcport);
    printf("%10s=%d\n", "dport", dstport);
    printf("%10s=%u\n", "seq", ack_seq_num);
    printf("%10s=%u\n", "ack", ack_num);
    printf("%10s=5\n", "offset");
    printf("%10s=000000(bit)\n", "reserved");
    printf("%10s=%s\n", "code", flag_str);
    printf("%10s=100\n", "window");
    printf("%10s=%d\n", "cksum", header_tcp->check);
    printf("%10s=00000\n", "urgptr");

    write_file(buf + MAX_IP_LENGTH, W_FILE_NAME_2, MAX_TCP_LENGTH + data_len);
    return;
}
void send_network(char *buf)
{
    struct ip *header_ip;
    struct tcphdr *header_tcp;
    header_ip = (struct ip *)buf;
    header_tcp = (struct tcphdr *)(buf + sizeof(struct ip));

    struct sockaddr_in *src_addr, *dst_addr;
    int offset, ttl;
    char flag[4], srcip[20], dstip[20];
    unsigned short int off = 0x4000; //010 0 0000 0000 0000 0000
    int data_len = get_config_int("application", "datalen");
    header_ip = (struct ip *)buf;
    src_addr = malloc(sizeof(struct sockaddr_in));
    dst_addr = malloc(sizeof(struct sockaddr_in));
    memset(src_addr, '\0', sizeof(struct sockaddr_in));
    memset(dst_addr, '\0', sizeof(struct sockaddr_in));

    get_config_str("network", "srcip", srcip);
    get_config_str("network", "dstip", dstip);
    ttl = get_config_int("network", "ttl");

    src_addr->sin_addr.s_addr = inet_addr(srcip);
    dst_addr->sin_addr.s_addr = inet_addr(dstip);

    //这里的flag和offset没有从文件中读，采取直接赋值，所以还有点小问题需要改进

    /*开始填充IP数据报的头部 */
    
    header_ip->ip_src = src_addr->sin_addr;                               //源地址，即攻击来源
    header_ip->ip_dst = dst_addr->sin_addr;                               //目的地址，即攻击目标
    header_ip->ip_len = htons(data_len + MAX_IP_LENGTH + MAX_TCP_LENGTH); //IP数据报及其载荷长度，整形且不要转字节序
    header_ip->ip_off = 0x40;                                             //有内核填写又问题
    header_ip->ip_v = IPVERSION;                                          //IPV4
    header_ip->ip_hl = sizeof(struct ip) >> 2;                            //IP数据报的头部长度
    header_ip->ip_tos = 0;                                                //服务类型
    header_ip->ip_id = 0;                                                 //IP id 由内核填写

    // tcp校验和
    header_tcp->check = htons(creator_check_sum(buf, IPPROTO_TCP));

    //重新修改刚刚计算tcp时被修改的地方
    header_ip->ip_p = IPPROTO_TCP; //传输层协议为TCP
    header_ip->ip_ttl = ttl;       //MAXTTL;
    //ip校验和
    header_ip->ip_sum = 0;                  //0表示禁用校验和，由网卡来校验
    header_ip->ip_sum = htons(creator_check_sum(buf, IPPROTO_IP));


    printf("IP包头基本信息:\n");
    printf("%10s=45(IPv4/20)\n", "ver+len");
    printf("%10s=00\n", "tos");
    printf("%10s=%d\n", "iplen", data_len);
    printf("%10s=%d\n", "id", header_ip->ip_id);
    printf("%10s=010\n", "frag");
    printf("%10s=0\n", "offset");
    printf("%10s=%d\n", "ttl", ttl);
    printf("%10s=%d\n", "proto", IPPROTO_TCP);
    printf("%10s=%x\n", "tcp cksum", header_tcp->check);
    printf("%10s=%x\n", "ip cksum", header_ip->ip_sum);
    printf("%10s=%s\n", "srcip", inet_ntoa(src_addr->sin_addr));
    printf("%10s=%s\n", "dstip", inet_ntoa(dst_addr->sin_addr));

    write_file(buf, W_FILE_NAME_4, MAX_IP_LENGTH + MAX_TCP_LENGTH + data_len);
    return;
}
void send_datalink(char *buf)
{
    struct _Ether_pkg pkg;

    char srcmac_str[18];
    char dstmac_str[18];
    unsigned char srcmac[6];
    unsigned char dstmac[6];
    int i = 0;

    get_config_str("datalink", "dstmac", dstmac_str);
    get_config_str("datalink", "srcmac", srcmac_str);

    for (i = 0; i < 6; i++)
    {
        char temp_src[2] = {srcmac_str[i * 3], srcmac_str[i * 3 + 1]};
        char temp_dst[2] = {dstmac_str[i * 3], dstmac_str[i * 3 + 1]};
        srcmac[i] = str_to_hex(temp_src);
        dstmac[i] = str_to_hex(temp_dst);
    }
    memset((char *)&pkg, '\0', sizeof(pkg));
    /* 填充ethernet包文 */
    memcpy((char *)pkg.ether_shost, (unsigned char *)srcmac, 6);
    memcpy((char *)pkg.ether_dhost, (unsigned char *)dstmac, 6);
    pkg.ether_type = htons(0x0800);

    memcpy(buf, (char *)&pkg, sizeof(struct _Ether_pkg));

    printf("以太网包头信息\n");
    printf("%10s=%s\n", "DstMAC", dstmac_str);
    printf("%10s=%s\n", "SrcMAC", srcmac_str);
    printf("%10s=0800(IP)\n", "Type");
    return;
}
void send_physics(char *buf)
{
    int data_len = get_config_int("application", "datalen");
    int length = MAX_ETHERNET_LENGTH + MAX_IP_LENGTH + MAX_TCP_LENGTH + data_len;
    write_file(buf, W_FILE_NAME_2, length);
}

/*--------------------------reciever函数-----------------------------------*/
void recieve_physics(unsigned char *buf)
{
    FILE *pFile;
    long lSize;
    char *buffer;
    size_t result;

    /* 若要一个byte不漏地读入整个文件，只能采用二进制方式打开 */
    pFile = fopen(W_FILE_NAME_2, "rb");
    /* 获取文件大小 */
    fseek(pFile, 0, SEEK_END);
    lSize = ftell(pFile);
    rewind(pFile);
    buffer = (char *)malloc(sizeof(char) * lSize);
    result = fread(buffer, 1, lSize, pFile);
    fclose(pFile);
    free(buffer);

    char *buffer_deal = (char *)malloc(sizeof(char) * lSize);
    int i = 0, j = 0;
    for (i = 0; i < lSize; i++)
    {
        if (buffer[i] == ' ' || buffer[i] == '\n')
            continue;
        buffer_deal[j++] = buffer[i];
    }

    i = 0;
    j = 0;
    for (i = 0; i < strlen(buffer_deal); i = i + 2)
    {
        char temp[2] = {buffer_deal[i], buffer_deal[i + 1]};
        buf[j++] = str_to_hex(temp);
    }
    j--;
}
void recieve_datalink(unsigned char *buf)
{
    struct _Ether_pkg *pkg = (struct _Ether_pkg *)buf;
    unsigned short int Type;

    unsigned char srcmac[6];
    unsigned char dstmac[6];
    int i = 0;

    memcpy((unsigned char *)srcmac, (char *)pkg->ether_shost, 6);
    memcpy((unsigned char *)dstmac, (char *)pkg->ether_dhost, 6);

    printf("以太网包头信息\n");
    printf("%10s=%02x:%02x:%02x:%02x:%02x:%02x\n", "DstMAC", dstmac[0], dstmac[1], dstmac[2], dstmac[3], dstmac[4], dstmac[5]);
    printf("%10s=%02x:%02x:%02x:%02x:%02x:%02x\n", "SrcMAC", srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]);
    printf("%10s=0x%02x%02x\n", "Type", buf[12], buf[13]);
    return;
}
int recieve_network(unsigned char *buf)
{
    struct ip *header_ip;
    header_ip = (struct ip *)buf;

    int data_len = (header_ip->ip_len >> 8);
    printf("IP包头基本信息:\n");
    printf("%10s=%x\n", "ver+len", (unsigned char)(((char *)(header_ip))[0]));
    printf("%10s=%02x\n", "tos", header_ip->ip_tos);
    printf("%10s=%d\n", "iplen", data_len);
    printf("%10s=0x%x\n", "id", header_ip->ip_id);
    printf("%10s=%d\n", "frag", (header_ip->ip_off >> 5)); //这里位数的处理有问题
    printf("%10s=0x%x\n", "offset", buf[7]);               //这里位数的处理有问题
    printf("%10s=%d\n", "ttl", header_ip->ip_ttl);
    printf("%10s=%d\n", "proto", IPPROTO_TCP);

    unsigned short check_ori = ntohs(header_ip->ip_sum);
    printf("%10s=%x", "ip cksum", ntohs(header_ip->ip_sum));
    header_ip->ip_sum = 0;
    unsigned short check = creator_check_sum(buf, IPPROTO_IP);
    printf("(实际计算结果%x)", check);
    if(check == check_ori)
        printf("一致\n");
    else
        printf("不一致\n");

    printf("%10s=%s\n", "srcip", inet_ntoa(header_ip->ip_src));
    printf("%10s=%s\n", "dstip", inet_ntoa(header_ip->ip_dst));

    return data_len;
}
void recieve_transport(unsigned char *buf)
{
    struct tcphdr *header_tcp;
    header_tcp = (struct tcphdr *)(buf + sizeof(struct ip));

    char flag_str[6] = {header_tcp->urg + '0', header_tcp->ack + '0',
                        header_tcp->psh + '0', header_tcp->rst + '0',
                        header_tcp->syn + '0', header_tcp->fin + '0'};

    //tcp校验和
    // header_tcp->check = creator_check_sum(buf, IPPROTO_TCP); ??????????

    printf("TCP包头基本信息:\n");
    printf("%10s=%d\n", "sport", ntohs(header_tcp->source));
    printf("%10s=%d\n", "dport", ntohs(header_tcp->dest));
    printf("%10s=0x%x\n", "seq", ntohs(header_tcp->seq));
    printf("%10s=0x%x\n", "ack", ntohs(header_tcp->ack_seq));
    printf("%10s=0x%x\n", "offset", (buf[MAX_IP_LENGTH + 12] >> 4));
    printf("%10s=0x%x\n", "reserved", header_tcp->res1);
    printf("%10s=%s\n", "code", flag_str);
    printf("%10s=%d\n", "window", ntohs(header_tcp->window));


    printf("%10s=0x%x", "tcp cksum", ntohs(header_tcp->check));
    unsigned short check_ori = ntohs(header_tcp->check);
    header_tcp->check=0;
    unsigned short check = creator_check_sum(buf, IPPROTO_TCP);
    printf("(实际计算结果%x)", check);
    if (check == check_ori)
        printf("一致\n");
    else
        printf("不一致\n");

    printf("%10s=0x%x\n", "urgptr", header_tcp->urg_ptr);

    return;
}
void recieve_application(unsigned char *buf, int data_len)
{
    write_file(buf, W_FILE_NAME_0, data_len);
    printf("TCP数据信息(len=%d)\n", data_len);
    int i = 0;
    while (i < data_len)
    {
        printf("%02X ", buf[i]);
        i++;
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

/*--------------------------随机+写文件函数-----------------------------------*/
unsigned char str_to_hex(const char *str)
{
    char *str_temp;
    unsigned char i = (unsigned char)strtol(str, &str_temp, 16); //十六进制
    return i;
}

void get_random_byte(char *buf, int length)
{
    srand(time(NULL)); //生成伪随机数种子
    // printf("random char %d:\n",length);
    int i = 0;
    for (i = 0; i < length; i++)
    {
        unsigned char temp_char = rand() % 256;
        /*按照16进制输出，补齐4位的宽度，补齐位为0，默认右对齐*/
        // printf("%02X\n", temp_char);
        // sprintf("%s%s",buf,temp_char);
        strcat(buf, &temp_char);
        // printf("times\n");
    }
    printf("\n");
    return;
}
void write_file(char *str_write, const char *file_name, int length)
{
    unsigned char *str_temp = str_write;
    FILE *fp = NULL;
    fp = fopen(file_name, "w");
    int i = 0, j = 0;
    // printf("strlen:%d\n",strlen(str_temp));
    while (i < length)
    {
        fprintf(fp, "%02X ", str_temp[i]);
        // printf("%02X ", str_temp[i]);
        i++;
        if (i % 16 == 0)
            fprintf(fp, "\n");
    }
    printf("\n");
    fclose(fp);
    return;
}

/*--------------------------tcp函数-----------------------------------*/

unsigned short creator_check_sum(const char *buf, int protocol)
{

    unsigned short *check_buf;

    unsigned short ret, tmp_ttl, tmp_ip_sum;
    int len;
    unsigned long sum = 0;

    //根据ip字段的第3,4字节的值得到数据包总长度，
    //然后对于奇数需要扩展1个字节
    len = ntohs(*(unsigned int *)(buf + 2));
    len = ((len + 1) / 2) * 2;

    switch (protocol) //IPPROTO_IP   = 0  IPPROTO_TCP  = 6
    {
    case IPPROTO_IP:
        //ip校验和参与计算的长度固定是20
        len = 20;
        // printf("len:%d \n", len);
        check_buf = (unsigned short *)buf;
        break;
    case IPPROTO_TCP:
        //tcp和udp的校验和计算，涉及到12字节的伪报头，
        //参与计算的长度，刚好是总长度减去8字节
        len -= 8;
        
        check_buf = (unsigned short *)(buf + 8);
        *check_buf = htons(0x0006);
        *(check_buf + 1) = *(unsigned short *)(buf + 2) - htons(20);
        break;

    default:
        break;
    }

    while (len > 1)
    {
        unsigned short int temp = *check_buf;
        temp = (temp >> 8) + (temp << 8);
        // printf("%x ", temp);
        sum += temp;
        check_buf++;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }
    // printf("%x \n", sum);
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    ret = (unsigned short)~sum;
    // printf("ret = %x\n",ret);
    return ret;
}

int creator_tcphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
                      struct sockaddr_in *dst_addr, int len_total)
{
    /*开始填充IP数据报的头部 */
    header_ip->ip_v = IPVERSION;               //IPV4
    header_ip->ip_hl = sizeof(struct ip) >> 2; //IP数据报的头部长度
    header_ip->ip_tos = 0;                     //服务类型
    header_ip->ip_len = htons(len_total);      //IP数据报及其载荷长度，整形且不要转字节序
    header_ip->ip_id = 0;                      //IP id 由内核填写
    header_ip->ip_off = 0;                     //有内核填写
    header_ip->ip_ttl = 30;                    //MAXTTL;
    header_ip->ip_p = IPPROTO_TCP;             //传输层协议为TCP
    header_ip->ip_sum = 0;                     //0表示禁用校验和，由网卡来校验
    header_ip->ip_src = src_addr->sin_addr;    //源地址，即攻击来源
    header_ip->ip_dst = dst_addr->sin_addr;    //目的地址，即攻击目标

    printf("dst address is %s\n", inet_ntoa(dst_addr->sin_addr));
    printf("src address is %s\n", inet_ntoa(src_addr->sin_addr));

    return 0;
}

int creator_header_tcp(struct tcphdr *header_tcp)
{
    /*开始填写TCP数据报 */
    // header_tcp->source = htons(SRC_PORT); //源端口
    // header_tcp->dest = htons(DST_PORT);   //目的端口
    header_tcp->seq = htons(100);     //发送序列号
    header_tcp->ack_seq = htons(200); //确认序号
    header_tcp->doff = 5;             //数据偏离位置即data off,其实就是header_tcp报头长度，
    //5表示5个双字，即5X4=20字节，通常是5
    //如果要使报文带有选项，可以设置为6或7或8
    //分别带有1个，2个，3个TCP选项

    //这里如果胡乱天，会导致构造的数据包无法被wireshark解析，
    //并提示[Malformed Packet: GSM over IP]
    header_tcp->res1 = 0;
    header_tcp->res2 = 0;
    header_tcp->urg = 0;
    header_tcp->ack = 1;
    header_tcp->psh = 1;
    header_tcp->rst = 0; //这里不启用rst字段，这样http请求就会更逼真
    header_tcp->syn = 0;
    header_tcp->fin = 0;

    header_tcp->window = htons(100);
    header_tcp->check = 0;
    header_tcp->urg_ptr = 0;

    return 0;
}
int creator_tcp(void)
{
    int sockfd, len_payload, len_total;
    struct sockaddr_in *src_addr, *dst_addr;

    char *buf, *payload;
    struct ip *header_ip;
    struct tcphdr *header_tcp;

    buf = malloc(200);
    payload = malloc(50);
    src_addr = malloc(sizeof(struct sockaddr_in));
    dst_addr = malloc(sizeof(struct sockaddr_in));

    header_ip = (struct ip *)buf;
    header_tcp = (struct tcphdr *)(buf + sizeof(struct ip));
    payload = buf + sizeof(struct ip) + sizeof(struct tcphdr);

    memset(buf, '\0', sizeof(buf));

    memset(src_addr, '\0', sizeof(struct sockaddr_in));
    memset(dst_addr, '\0', sizeof(struct sockaddr_in));

    // len_payload = payload_tcp(payload);

    len_total = sizeof(struct ip) + sizeof(struct tcphdr) + len_payload;

    //构建原始套接字
    //sockfd = sock_init_tcp(src_addr, dst_addr);

    //初始化ip报头
    creator_tcphdr_ip(header_ip, src_addr, dst_addr, len_total);

    //初始化tcp报头，并填充数据
    creator_header_tcp(header_tcp);

    //ip校验和是否填充无所谓，网卡会自动计算出来
    header_ip->ip_sum = creator_check_sum(buf, IPPROTO_IP);

    //tcp校验和
    header_tcp->check = creator_check_sum(buf, IPPROTO_TCP);

    //发送tcp数据包
    //send_tcp(sockfd, dst_addr, buf, len_payload);

    return 0;
}
