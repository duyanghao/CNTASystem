//catch.c
#include "protocol.h"
#define TIME_WAIT 60000 //等待时间戳
static char gl[20]="ip and (udp or tcp)"; //过滤表达式

static FILE *fp;
static void display(const u_char *packet,int len); //Display 解析显示
static void getpacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *packet); //回调函数
static void catch_packet(const u_int te); //循环抓包函数（核心函数）
static u_char Is_correct_fomt(const u_char *packet); //是否为以太网帧
static u_int Power(const u_int en); //计算10^en
static u_int Input(); //输入检验
static u_int Power(const u_int en){ //计算10^en
	if(en==0)
		return 1;
	else
		return 10*Power(en-1);
}
static u_int Input(){ //输入检验，对输入的时间轮整数进行有效性检验
	u_int pivot=0;
	u_int trag=0;
	u_int input[200];
	char tmp;
	while(1){
		tmp=getchar();
		if(tmp=='\n')
			break;
		if(tmp>'0' && tmp<='9'){
			input[pivot++]=tmp-'0';
			trag=1;
			while(1){
				tmp=getchar();
				if(tmp>='0' && tmp<='9')
					input[pivot++]=tmp-'0';
				else
					break;
			}
		}
		if(tmp=='\n')
			break;
		while(trag){
			tmp=getchar();
			if(tmp=='\n')
				break;
		}
		if(tmp=='\n')
			break;
	}
	if(!trag){
		printf("error input\n");
		exit(-1);
	}
	else{
		u_int Sum=0;
		u_int i;
		for(i=0;i<pivot;i++)
			Sum+=Power(i)*input[pivot-i-1];
		return Sum;
	}
}
int main(int argc,char **argv){ //主体
	u_int te;
	printf("please input the minutes you want to catch:\n");
	//scanf("%d",&te);
	te=Input(); //获取输入
	//printf("%d\n",te);
	catch_packet(te); //循环抓包函数
	exit(0);
}
static u_char Is_correct_fomt(const u_char *packet){ //判断抓取的包是否为以太网包,以及IPV4和TCP OR UDP包
	if(packet[12]!=0x08 || packet[13]!=0x00)
		return 0;
	if((packet[14]&(0xf0))!=0x40)
		return 0;
	if(packet[23]!=17 && packet[23]!=6)
		return 0;
	return 1;
}
static void catch_packet(const u_int te){ //循环抓包函数(进程主要函数)
	u_int tme=te; //loop time
	char errbuf[PCAP_ERRBUF_SIZE],*devstr;
	devstr=pcap_lookupdev(errbuf); //获取网络接口
	pcap_t *device;
	bpf_u_int32 netp,maskp; // ip and ip mask
	int ret; //return value
	char *net,*mask;
	struct in_addr addr;
	struct bpf_program filter;
	int i,j=1;
	pid_t pid;
	if(devstr)
		printf("success device is %s:\n",devstr);
	else{
		printf("error:%s\n",errbuf);
		exit(-1);
	}
	device=pcap_open_live(devstr,65535,1,TIME_WAIT,errbuf);   //打开网络接口
	if(!device){
	 	printf("error: pcap_open_live(): %s\n",errbuf);
		exit(-1);
	}
	ret=pcap_lookupnet(devstr,&netp,&maskp,errbuf); //获取指定网络设备的网络号和掩码
	if(ret==-1){
		printf("pcap_lookupnet() error: %s\n",errbuf);
		exit(-1);
	}
	addr.s_addr=netp;
	net=inet_ntoa(addr);
	if(!net){
		perror("inet_ntoa() ip error\n");
		exit(-1);
	}
	printf("ip: %s\n",net);
	addr.s_addr=maskp;
	mask=inet_ntoa(addr);
	if(!mask){
		perror("inet_ntoa() sub mask error: \n");
		exit(-1);
	}
	printf("sub mask: %s\n",mask);
	ret=pcap_compile(device,&filter,gl,1,maskp); //编译过滤表达式
	if(ret==-1){
		perror("pcap_compile error\n");
		exit(-1);
	}
	ret=pcap_setfilter(device,&filter); //设置过滤表达式
	if(ret==-1){
		perror("pcap_setfilter error\n");
		exit(-1);
	}
	while(tme--){ //循环读取tme轮
		printf("round:%d\n",j++);
		i=0;
		fp=fopen("record","w+"); //0 && r & w
		//init pcap file
		pcap_header tmp;
		tmp.flag=0xd4c3b2a1;
		memset(tmp.info,0,sizeof(tmp.info));
		if(fwrite(&tmp,sizeof(pcap_header),1,fp)!=1){
			perror("fwrite error\n");
			exit(-1);
		}
		ret=pcap_dispatch(device,-1,getpacket,(u_char*)&i); //捕获一分钟数据
		fclose(fp);
		printf("\ntotal packets is:=%d\n",ret);
		if((pid=fork())<0){ //生成子进程对pcap离线文件进行分析与统计
			perror("error\n");
			exit(-1);
                }
                else if(pid==0){
			if(execlp("./display","display","/home/duyanghao/zonghe_pro/net_pro/record",(char *)0)<0) //调用display.c函数
				perror("execlp error\n");
			exit(-1);
		}
		if(waitpid(pid,NULL,0)<0) //父进程等待子进程
			perror("waitpid error\n");

	}
	pcap_close(device); //关闭设备
	return ;
}
static void getpacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *packet){ //回调函数
	printf("\npacket numbers is:%d\n",++(*arg));
	if(pkthdr->len!=pkthdr->caplen){
		perror("untotal packet\n");
		return ;
	}
	if(Is_correct_fomt(packet)==0){
		printf("Not ETHER PACKET\n");
		return ;
	}
	//...
	if(fwrite(pkthdr,sizeof(struct pcap_pkthdr),1,fp)!=1){
		perror("fwrite error\n");
		//return ;
		exit(-1);
	}
	if(fwrite(packet,sizeof(u_char),pkthdr->len,fp)!=pkthdr->len){
		perror("fwrite error\n");
		exit(-1);
		//return ;
	}
	display(packet,pkthdr->len);
	return ;
}
static void display(const u_char *packet,int len){ //解析获取的数据包
	u_char i,Cnt=0;
	u_char protocol;
	u_char tmp=packet[ETHER_LEN];
	printf("================================\n");
	printf("ETHER_header analy:\n");
	for(i=0;i<ETHER_LEN;i++){ //ETHER_header
		if(i==0)
			printf("MAC_DES:");
		else if(i==6)
			printf("	MAC_SRC:");
		else if(i==12)
			printf("	TOP_PROTOCOL:");
		printf("%02x",packet[i]);
	}
	printf("\n");
	//ip_header analy
	printf("\nIP_header analy:\n");
        //version
        printf("VERSION:");
	tmp=packet[ETHER_LEN]&(0xf0);
	tmp>>=4;
	printf("%02x",tmp);
	//header_len
	printf(" HEADER_LEN:");
	tmp=packet[ETHER_LEN]&(0x0f);
	printf("%02x",tmp);
	//tos
	printf(" TOS:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	//total len
	printf(" PACKET_LEN:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	//identifation
	printf(" ID:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	//sym
	printf("\nSYM:");
	Cnt++;
	tmp=packet[ETHER_LEN+Cnt]&(0xE0);
	tmp>>=5;
	printf("%02x",tmp);
	//MF
	//tmp&=(0x01);
	printf(" MF=%02x",tmp&(0x01));
	//DF
	//tmp&=(0x02);
	//tmp>>=1;
	printf(" DF=%02x",(tmp&(0x02))>>1);

	//printf("%02x",tmp);
	//packet offset
	printf(" PACKET_OFFSET:");
	tmp=packet[ETHER_LEN+Cnt]&(0x1f);
	printf("%02x",tmp);
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	//ttl
	printf(" TTL:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	//protocol
	printf(" TOP_PROTOCOL:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
        //...............
        protocol=packet[ETHER_LEN+Cnt];
        //header_checksum
        printf(" CHECK_SUM:");
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%02x",packet[ETHER_LEN+Cnt]);

	//source ip
	printf(" SCR_IP:");
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d",packet[ETHER_LEN+Cnt]);


	//des ip
	printf(" DES_IP:");
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d.",packet[ETHER_LEN+Cnt]);
	Cnt++;
	printf("%d",packet[ETHER_LEN+Cnt]);

	printf("\n");
	//
	if(protocol==6){
		printf("\ntcp_header analys:\n");
		tmp=packet[ETHER_LEN]&(0x0f);
		Cnt=tmp*4-1;
		printf("SRC_PORT:");
		Cnt++;  //scr port
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		printf(" DES_PORT:");
		Cnt++; //des port
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		//sequence
		printf(" SEQ:");
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		//ack
		printf(" ACK:");
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		//header_len
		printf(" HEAD_LEN:");
		Cnt++;
		tmp=packet[ETHER_LEN+Cnt]&(0xf0);
		tmp>>=4;
		printf("%02x",tmp);
		//control flags
		printf("\nCON_FLAGS:");
		Cnt++;
		tmp=packet[ETHER_LEN+Cnt]&(0x3f);
		printf("%02x",tmp);
		//URG
		//tmp&=(0x20);
		//tmp>>=5;
		printf(" URG=%02x",(tmp&(0x20))>>5);
		//ACK *
		//tmp&=(0x10);
		//tmp>>=4;
		printf(" ACK=%02x",(tmp&(0x10))>>4);
		//PSH
		//tmp&=(0x08);
		//tmp>>=3;
		printf(" PSH=%02x",(tmp&(0x08))>>3);
		//RST
		//tmp&=(0x04);
		//tmp>>=2;
		printf(" RST=%02x",(tmp&(0x04))>>2);
		//SYN
		//tmp&=(0x02);
		//tmp>>=1;
		printf(" SYN=%02x",(tmp&(0x02))>>1);
		//FIN
		//tmp&=(0x01);
		printf(" FIN=%02x",tmp&(0x01));
		//printf("%02x",tmp);
		//windows
		printf(" WINDOWS:");
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);

		//checksum
		printf(" CHECKSUM:");
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		//urg pointer
		printf(" URG_POINT:");
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
		Cnt++;
		printf("%02x",packet[ETHER_LEN+Cnt]);
	}
        else if(protocol==17){
        	printf("\nudp_header ansly:\n");
        	tmp=packet[ETHER_LEN]&(0x0f);
        	Cnt=tmp*4-1;
        	//src port
        	printf("SRC_PORT:");
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	//des port
        	printf(" DES_PORT:");
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	//udp len
        	printf(" UDP_LEN:");
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	//check sum
        	printf(" CHECK_SUM:");
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        	Cnt++;
        	printf("%02x",packet[ETHER_LEN+Cnt]);
        }
	printf("\n===============================\n");
	printf("\n\n");
        return ;
}
