#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/if_arp.h>

#define MAC_ADDR_LEN 6
/* MAC addresses to be natted*/
#if 0
#define MAC_01 {0x0,0x14,0x22,0x72,0x27,0x38} /*build server01*/
#define MAC_02 {0x0,0x1A,0xA0,0x1E,0x39,0x97} /*build server04*/
#define MAC_03 {0x0,0x1B,0x11,0xB1,0x26,0x15} /*smokeserver*/
#endif

#define MAC_04 {0x00,0x01,0xAF,0x18,0xF6,0x97} /*F101_11 -> 192.168.100.201 */
#define MAC_05 {0x00,0xC0,0x8B,0x09,0x44,0x4D} /*F101_03 -> 192.168.100.202 */

 
/*New IP addresses to be assigned*/
#if 0
#define IP_NEW_01 0xAC1001DC    /*172.16.1.220*/
#define IP_NEW_02 0xAC1001DD    /*172.16.1.221*/
#define IP_NEW_03 0xAC1001DE	/*172.16.1.222*/
#endif

#define IP_NEW_04 0xC0A864C9	/*192.168.100.201*/
#define IP_NEW_05 0xC0A864CA    /*192.168.100.202*/

struct map{
	__u32 new_ip;
	__u32 old_ip;
	__u8  *mac;
	struct list_head list;
}map_list;
	
static struct nf_hook_ops netfilter_ops_in; 
static struct nf_hook_ops netfilter_ops_out;

/* MACs to IPs*/
static unsigned char macs[][MAC_ADDR_LEN] = {MAC_04, MAC_05};
/*
MAC_01 -> IP_NEW_01
MAC_02 -> IP_NEW_02

00:01:AF:18:F6:97: 192.168.100.1 -> 192.168.100.201
00:C0:8B:09:44:4D: 192.168.100.1 -> 192.168.100.202
*/
static unsigned int ip_new_saddr[] = {IP_NEW_04, IP_NEW_05};


static void calc_ip_csum (struct iphdr *iph)
{
	iph->check = 0;
        iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

static void calc_udp_csum( struct iphdr *iph, struct udphdr *udph, unsigned int udplen)
{
	udph->check = 0;
        udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, IPPROTO_UDP,
                                         csum_partial((char *)udph, udplen, 0));
}

static struct udphdr * get_udph( struct iphdr *iph)
{
	/*
        The value of the iph->ihl is 32-bit (4 bytes) multiples,
        so we have to multiply by 4 (bytes)
        */
	return (struct udphdr *)((char *)iph + (iph->ihl * 4));
}

static unsigned int get_udp_len( struct sk_buff *skb )
{
	/* 
	The value of the iph->ihl is 32-bit (4 bytes) multiples, 
	so we have to multiply by 4 (bytes)
	*/
	return ((skb)->len - (skb->nh.iph->ihl) * 4);
}

static void init_mapping(void)
{
	struct map *tmp;
	int macs_array = ARRAY_SIZE(macs);
	unsigned int i;
	
	for(i=0; i<macs_array; i++){
		/* adding elements to mylist */
		tmp = (struct map *)kmalloc(GFP_KERNEL,sizeof(struct map));
		tmp->new_ip = ip_new_saddr[i];
		tmp->mac = macs[i];
		/* add the new item 'tmp' to the list of items in mylist */
		list_add(&(tmp->list), &(map_list.list));
	}
}

static struct map * mac_compare(struct ethhdr *eth){

	struct list_head *pos;
	struct map *tmp;

	list_for_each(pos, &map_list.list){

		tmp = list_entry(pos, struct map, list);
		if (!memcmp(tmp->mac, eth->h_source, MAC_ADDR_LEN))
		{
			return tmp;		
		}
	}
	
	return NULL;
}

static struct map * ip_compare(struct iphdr *iph){

	struct list_head *pos;
	struct map *tmp;

	list_for_each(pos, &map_list.list){

		tmp = list_entry(pos, struct map, list);
		if (iph->daddr == tmp->new_ip)
		{
			return tmp;		
		}
	}
	
	return NULL;
}

static void list_free(void)
{
	struct list_head *pos, *q;
	struct map *tmp;
	
	list_for_each_safe(pos, q, &map_list.list){
		 tmp= list_entry(pos, struct map, list);
		 list_del(pos);
		 kfree(tmp);
	}
}
/*
static int add_to_arp_table()
{
	struct arpreq r;
	r.arp_pa.sa_family = AF_INET;


	arp_req_set();

	return SUCCESSFUL;
}
*/
/* Function prototype in <linux/netfilter> */
static unsigned int in_hook(unsigned int hooknum,  
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{

	if( (skb) && (*skb)){
		
		struct ethhdr *eth;
		struct map *current;
		struct iphdr *iph = (*skb)->nh.iph;
	
		eth = eth_hdr(*skb);

		/* Mapping only for UDP protocol */
		if(eth && (iph->protocol == IPPROTO_UDP ))
		{

			if( (current = mac_compare(eth)))
			{
				struct udphdr *udph;

				/* changing source IP address*/
				current->old_ip = iph->saddr;
				iph->saddr = current->new_ip;
				calc_ip_csum(iph);

				udph = get_udph(iph);

				if (udph->check) 
				{
					int udplen = get_udp_len(*skb);
					calc_udp_csum(iph, udph, udplen);
				}
				
				/*add_to_arp_table();*/
			 }
		}
	}

	return NF_ACCEPT; /* Accept ALL Packets */
}


static unsigned int out_hook(unsigned int hooknum,  
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{

	IPCB(*skb)->flags |= IPSKB_TRANSLATED;

	if( (skb) && (*skb) && ((*skb)->nh.iph->protocol == IPPROTO_UDP )){

		struct iphdr *iph = (*skb)->nh.iph;
		struct map *current;

		if( (current = ip_compare(iph)) )
		{
	
			struct udphdr *udph = (*skb)->h.uh;
			/*taking the original source IP address back */
			iph->daddr = current->old_ip;			
			calc_ip_csum(iph);
			udph = get_udph(iph);
		
			if (udph->check) {
			        calc_udp_csum(iph, udph, get_udp_len(*skb));

				/*This is to nobody recalculate the udp checksum after me*/
				(*skb)->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	}
	return NF_ACCEPT; /* Accept ALL Packets */
}

int init_module()
{
	INIT_LIST_HEAD(&map_list.list);
    	init_mapping();
				
	netfilter_ops_in.hook                   =       in_hook;
        netfilter_ops_in.pf                     =       PF_INET;
        netfilter_ops_in.hooknum                =       NF_IP_LOCAL_IN;
        netfilter_ops_in.priority               =       NF_IP_PRI_FIRST;
        netfilter_ops_out.hook                  =       out_hook;
        netfilter_ops_out.pf                    =       PF_INET;
        netfilter_ops_out.hooknum               =       NF_IP_LOCAL_OUT;
        netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops_in);
        nf_register_hook(&netfilter_ops_out);

	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);
	list_free();
}
