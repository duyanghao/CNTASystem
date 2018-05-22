//display.c

#include "protocol.h"
#define MAX_LEN 65536 //��ȡ����󳤶ȣ�ʵ����û����ô�ࣩ
#define MOD 99991 //hash����
#define DNS_PORT 53 //DNS�˿ں�
#define HTTP_PORT 80 //HTTP�˿ں�
#define PPTV_PORT 7010 //PPTV�˿ں�
typedef struct _hash_link{ //��pcap�ļ��������ɵ���Ԫ��
	u_short src_port;
	u_short des_port;
	u_int src_ip;
	u_int des_ip;
	u_int len;
}*point_hash;
typedef struct  _hash_node{ //hash link ��ϣ�ڵ�
	u_short src_port; //src port
	u_short des_port; //des port
	u_int src_ip; //src ip
	u_int des_ip; //des ip
	u_int top_low_len[2];
	u_int top_low_cnt[2];
	u_char sym;
	struct _hash_node *next;
}*point_node; //tcp 0,udp 1
struct _hash_node hash_node[2][MOD]; //TCP����UDP��
u_char flag[2][MOD]; //��־hash
u_char data[MAX_LEN]; //��pcap�ļ��ж�ȡ������
//
u_char ack,syn; //ACK&SYN
//�ܹ������������е�����ͳ��
u_int top_cnt=0;//top number
u_int low_cnt=0;//low number
u_int top_len=0;//top len
u_int low_len=0;//low len
//DNS��������������ͳ��
u_int dns_top_cnt=0;
u_int dns_top_len=0;
u_int dns_low_cnt=0;
u_int dns_low_len=0;
//HTTP��������������ͳ��
u_int http_top_cnt=0;;
u_int http_top_len=0;
u_int http_low_cnt=0;
u_int http_low_len=0;
//PPTV��������������ͳ��
u_int pptv_top_cnt=0;
u_int pptv_top_len=0;
u_int pptv_low_cnt=0;
u_int pptv_low_len=0;
//...
static void show_node(const point_node entity); //��ʾ�ڵ�
static u_char Is_equal(const point_hash p,const point_node q); //�ж��Ƿ���ͬ
static void Init_hash(); //��ʼ��hash
static void Add_cal(); //��������
static u_short cal_key(u_short src_port,u_short des_port,u_int src_ip,u_int des_ip); //����key
static void Insert_hash(point_hash entity,const u_char type); //����hash
static void decode_file(const char *path); //�����ļ�
static void display(); //��ʾ���ͳ�Ƶ�����
static void Static_cal(const point_node entity);//ͳ������

int main(int argc,char **argv){ //���庯��,���и����̴�pcap�ļ������ӽ���
	if(argc!=2){
		perror("arg too little\n");
		exit(-1);
	}
	Init_hash(); //��ʼ��hash
	decode_file(argv[1]); //��pcap�ļ�����
	printf("decode end here\n");
	Add_cal(); //ͳ������
	display(); //��ʾ
	printf("\n");
	exit(0);
}
static void show_node(const point_node entity){ //��ʾhash�ڵ�
	printf(" SRC_IP:%d.%d.%d.%d ",(entity->src_ip&(0xff000000))>>24,(entity->src_ip&(0x00ff0000))>>16,(entity->src_ip&(0x0000ff00))>>8,entity->src_ip&(0x000000ff));
	printf(" SRC_PORT:%4x ",entity->src_port);
	printf(" DES_IP:%d.%d.%d.%d ",(entity->des_ip&(0xff000000))>>24,(entity->des_ip&(0x00ff0000))>>16,(entity->des_ip&(0x0000ff00))>>8,entity->des_ip&(0x000000ff));
	printf(" DES_PORT:%4x  ",entity->des_port);
	printf("\n");
	printf(" TOP_LEVEL_LEN:%8x  ",entity->top_low_len[0]);
	printf(" TOP_LEVEL_CNT:%8x  ",entity->top_low_cnt[0]);
	printf(" LOW_LEVEL_LEN:%8x  ",entity->top_low_len[1]);
	printf(" LOW_LEVEL_CNT:%8x  ",entity->top_low_cnt[1]);
	printf(" FLAG:%02x",entity->sym);
	printf("\n");
}
static void Static_cal(const point_node entity){ //ͳ���������ú���
	//total
	top_len+=entity->top_low_len[0];
	low_len+=entity->top_low_len[1];
	top_cnt+=entity->top_low_cnt[0];
	low_cnt+=entity->top_low_cnt[1];
	//dns
	if(entity->src_port==DNS_PORT || entity->des_port==DNS_PORT){
		dns_top_len+=entity->top_low_len[0];
		dns_low_len+=entity->top_low_len[1];
		dns_top_cnt+=entity->top_low_cnt[0];
		dns_low_cnt+=entity->top_low_cnt[1];
	}
	if(entity->src_port==HTTP_PORT || entity->des_port==HTTP_PORT){
		http_top_len+=entity->top_low_len[0];
		http_low_len+=entity->top_low_len[1];
		http_top_cnt+=entity->top_low_cnt[0];
		http_low_cnt+=entity->top_low_cnt[1];
	}
	if(entity->src_port==PPTV_PORT || entity->des_port==PPTV_PORT){
		pptv_top_len+=entity->top_low_len[0];
		pptv_low_len+=entity->top_low_len[1];
		pptv_top_cnt+=entity->top_low_cnt[0];
		pptv_low_cnt+=entity->top_low_cnt[1];
	}
}
static void Add_cal(){ //����hash��ͳ����������
	u_int i,num;
	u_char type;
	point_node pivot, ptmp;
	printf("TCP HASH LINK SHOW:\n");
	type=0; //tcp
	for(i=0;i<MOD;++i){
		if(flag[type][i]){
			pivot=&hash_node[type][i];
			printf("\nkey is: %08x\n",i);
			printf("key node show below:\n");
			num=1;
			while(pivot){
				show_node(pivot);
				Static_cal(pivot);
				ptmp=pivot->next;
				if(num>1) //free heap size
					free(pivot);
				pivot=ptmp;
			}
		}
	}
	printf("SHOW END HERE\n");
	printf("\nUDP HASH LINK SHOW:\n");
	type=1; //udp
	for(i=0;i<MOD;++i){
		if(flag[type][i]){
			pivot=&hash_node[type][i];
			printf("\nkey is: %08x\n",i);
			printf("key node show below:\n");
			num=1;
			while(pivot){
			        show_node(pivot);
			        Static_cal(pivot);
			        ptmp=pivot->next;
			        if(num>1)
			        	free(pivot);
			        pivot=ptmp;
			}

		}
	}
	printf("SHOW END HERE\n");
}
static void Init_hash(){ //��ʼ��hash��
	int i;
	for(i=0;i<MOD;++i){
		flag[0][i]=0;
		flag[1][i]=0;
	}
	return ;
}
static u_short cal_key(u_short src_port,u_short des_port,u_int src_ip,u_int des_ip){ //����keyֵ
	u_short tmp=src_port^des_port;
	u_int tmp1=src_ip|des_ip;
	u_int tmp2=(u_int)tmp;
	return (tmp1&tmp2)%MOD;
}
static u_char Is_equal(const point_hash p,const point_node q){ //�ж������Ƿ���ͬ
	if(p->src_port==q->src_port && p->src_ip==q->src_ip && p->des_port==q->des_port && p->des_ip==q->des_ip || (p->src_port==q->des_port && p->src_ip==q->des_ip && p->des_port==q->src_port && p->des_ip==q->src_ip))
		return 1;
	return 0;
}

static void Insert_hash(point_hash entity,const u_char type){ //hash insert 0-tcp/1-ucp
	u_short key=cal_key(entity->src_port,entity->des_port,entity->src_ip,entity->des_ip);
	u_char trag=0;
	point_node pivot;
	if(flag[type][key]){
		pivot=&hash_node[type][key];
		while(pivot){
			if(Is_equal(entity,pivot)==1){
				//spe terminal bind
				if(entity->src_ip==pivot->src_ip){
					pivot->top_low_len[pivot->sym]+=entity->len;
					pivot->top_low_cnt[pivot->sym]++;
				}
				else{
					pivot->top_low_len[(pivot->sym+1)%2]+=entity->len;
					pivot->top_low_cnt[(pivot->sym+1)%2]++;
				}
				free(entity);
				//trag
				trag=1;
				break;

			}
			pivot=pivot->next;
		}
	}
	if(!trag){
		key=cal_key(entity->des_port,entity->src_port,entity->des_ip,entity->src_ip);
		if(!flag[type][key]){
			flag[type][key]=1;
			hash_node[type][key].src_port=entity->src_port;
			hash_node[type][key].src_ip=entity->src_ip;
			hash_node[type][key].des_port=entity->des_port;
			hash_node[type][key].des_ip=entity->des_ip;
			if(type==1){
				hash_node[type][key].top_low_len[0]=entity->len;
				hash_node[type][key].top_low_len[1]=0;
				hash_node[type][key].top_low_cnt[0]=1;
				hash_node[type][key].top_low_cnt[1]=0;
				hash_node[type][key].sym=0;
			}
			else{
				if(syn==1 && ack==0 || syn==0){
					hash_node[type][key].top_low_len[0]=entity->len;
					hash_node[type][key].top_low_len[1]=0;
					hash_node[type][key].top_low_cnt[0]=1;
					hash_node[type][key].top_low_cnt[1]=0;
					hash_node[type][key].sym=0;
				}
				else{
					hash_node[type][key].top_low_len[0]=0;
					hash_node[type][key].top_low_len[1]=entity->len;
					hash_node[type][key].top_low_cnt[0]=0;
					hash_node[type][key].top_low_cnt[1]=1;
					hash_node[type][key].sym=1;
				}
			}
			free(entity); //free
			hash_node[type][key].next=NULL;
		}
		else{
			pivot=&hash_node[type][key];
			while(pivot){
				if(Is_equal(entity,pivot)==1){
					if(entity->src_ip==pivot->src_ip){
						pivot->top_low_len[pivot->sym]+=entity->len;
						pivot->top_low_cnt[pivot->sym]++;
					}
					else{
						pivot->top_low_len[(pivot->sym+1)%2]+=entity->len;
						pivot->top_low_cnt[(pivot->sym+1)%2]++;
					}
					free(entity);
					//trag
					trag=1;
					break;
				}
				pivot=pivot->next;
			}
			if(!trag){
				point_node tmp=(point_node)malloc(sizeof(struct _hash_node));
				tmp->src_ip=entity->src_ip;
				tmp->des_ip=entity->des_ip;
				tmp->src_port=entity->src_port;
				tmp->des_port=entity->des_port;
				if(type==1){
					tmp->top_low_len[0]=entity->len;
					tmp->top_low_len[1]=0;
					tmp->top_low_cnt[0]=1;
					tmp->top_low_cnt[1]=0;
					tmp->sym=0;
				}
				else{
					if(syn==1 && ack==0 || syn==0){
						tmp->top_low_len[0]=entity->len;
						tmp->top_low_len[1]=0;
						tmp->top_low_cnt[0]=1;
						tmp->top_low_cnt[1]=0;
						tmp->sym=0;
					}
					else{
						tmp->top_low_len[0]=0;
						tmp->top_low_len[1]=entity->len;
						tmp->top_low_cnt[0]=0;
						tmp->top_low_cnt[1]=1;
						tmp->sym=1;
					}

				}
				tmp->next=hash_node[type][key].next;
				hash_node[type][key].next=tmp;
				free(entity);
			}
		}
	}
	return ;
}
static void decode_file(const char *path){ //��pcap�ļ����н���,������Ĵ���
	point_hash entity;
	FILE *fp;
	pcap_header right;
	struct pcap_pkthdr used;
	fp=fopen(path,"r");
	u_char rlen=ETHER_LEN+IP_LEN_MIN;
	u_char ip_header;
	u_int ip_tlen;
	u_char protocol;
	u_short offset;
	//
	if(fp==NULL){
		perror("fopen error\n");
		exit(-1);
	}
	if(fseek(fp,0,SEEK_SET)!=0){
		perror("fseek error\n");
		exit(-1);
	}
	if(fread(&right,sizeof(pcap_header),1,fp)!=1){
		perror("fread error\n");
		exit(-1);
	}
	if(right.flag!=0xd4c3b2a1){
		printf("%s is not the pcap file\n",path);
		exit(-1);
	}
	while(1){
		if(fread(&used,sizeof(struct pcap_pkthdr),1,fp)!=1){ //�������ļ�β��
			break;
		}
		ip_tlen=(u_int)used.len-ETHER_LEN;
		if(fread(data,sizeof(u_char),rlen,fp)!=rlen){ //����̫��ͷ��ip��ͷ
			perror("fread error\n");
			exit(-1);
		}
		if(data[12]!=0x08 || data[13]!=0x00){ //�ж��Ƿ�ΪIPV4����
			printf("====proto:%02x",data[12]);
			printf("%02x\n",data[13]);
			perror("data is not in ETHER\n");
			int i;
			for(i=0;i<16;i++)
				printf(" %02x",data[i]);
			printf("\n===last packet len:%d\n",ip_header);
			printf("====last packet total len %d\n",ip_tlen);
			exit(-1);
		}
		if(data[ETHER_LEN+9]!=6 && data[ETHER_LEN+9]!=17){ //�ж��Ƿ�ΪTCP OR UDP
			perror("not tcp or udp packets\n");
			exit(-1);
		}
		entity=(struct _hash_link *)malloc(sizeof(struct _hash_link)); //��ȡԴIP��Ŀ��IP
		entity->src_ip=ntohl(*(u_int *)(&data[ETHER_LEN+12]));
		entity->des_ip=ntohl(*(u_int *)(&data[ETHER_LEN+16]));
		ip_header=data[ETHER_LEN]&(0x0f); //����IP�ײ�����
		ip_header*=4;
		protocol=data[ETHER_LEN+9];


		entity->len=ip_tlen+ETHER_LEN;

		if(fseek(fp,ip_header-IP_LEN_MIN,SEEK_CUR)!=0){
			perror("fseek error\n");
			exit(-1);
		}
		if(fread(data,sizeof(u_char),4,fp)!=4){ //��ȡ�˿�
			perror("fread error\n");
			exit(-1);
		}
		entity->src_port=ntohs(*(u_short *)(&data[0])); //��ȡԴ�˿���Ŀ�Ķ˿�
		entity->des_port=ntohs(*(u_short *)(&data[2]));

		//change to next packet
		offset=ip_tlen-ip_header-4;
		if(protocol==6){ //��ΪTCP���ģ�����Ҫ��ȡ16�ֽڣ��Խ���ACK��SYN�ֶ�
			if(fread(data,sizeof(u_char),16,fp)!=16){
				perror("fread error\n");
				exit(-1);
			}
			ack=data[9]&(0x10);
			ack>>=4;
			syn=data[9]&(0x02);
			syn>>=1;
			offset-=16;
		}
		if(fseek(fp,offset,SEEK_CUR)!=0){
			perror("fseek error\n");
			exit(-1);
		}

		//check................
		/*printf("======\n");
		printf(" %08x",entity->src_ip);
		printf(" %08x",entity->des_ip);
		printf(" %04x",entity->src_port);
		printf(" %04x",entity->des_port);
		printf(" %08x",entity->len);*/
		//printf("\n");
		//check end
		if(protocol==6) //tcp
			Insert_hash(entity,0);
		else //udp
			Insert_hash(entity,1);
	}
}
static void display(){//��ʾͳ����Ϣ
	//total data
	printf("----TOTAL DATA STATICS:\n");
	printf("-------top level data numbers is: %d\n",top_cnt);
	printf("-------top level data total len is: %d\n",top_len);
	printf("-------low level data numbers is: %d\n",low_cnt);
	printf("-------low level data total len is: %d\n",low_len);
	//dns data
	printf("----DNS DATA STATICS:\n");
	printf("-------dns top level data numbers is: %d\n",dns_top_cnt);
	printf("-------dns_top level data len is: %d\n",dns_top_len);
	printf("-------dns_low level data numbers is: %d\n",dns_low_cnt);
	printf("-------dns_low level data len is: %d\n",dns_low_len);
	//http data
	printf("----HTTP DATA STATICS:\n");
	printf("-------http top level data numbers is: %d\n",http_top_cnt);
        printf("-------http_top level data len is: %d\n",http_top_len);
        printf("-------http_low level data numbers is: %d\n",http_low_cnt);
        printf("-------http_low level data len is: %d\n",http_low_len);
	//pptv data
	printf("----PPTV DATA STATIC:\n");
	printf("-------pptv top level data numbers is: %d\n",pptv_top_cnt);
	printf("-------pptv top level data len is: %d\n",pptv_top_len);
	printf("-------pptv low level data numbers is: %d\n",pptv_low_cnt);
	printf("-------pptv low level data len is: %d\n",pptv_low_len);
        //end
        printf("DATA STATICS END HERE\n\n");
}
