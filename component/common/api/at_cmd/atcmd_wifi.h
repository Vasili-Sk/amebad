#ifndef __ATCMD_WIFI_H__
#define __ATCMD_WIFI_H__
#include "main.h"
#include "lwip_netconf.h"
#include "wifi_structures.h"
#include <wlan_fast_connect/example_wlan_fast_connect.h>

#ifndef WLAN0_NAME
  #define WLAN0_NAME		"wlan0"
#endif
#ifndef WLAN1_NAME
  #define WLAN1_NAME		"wlan1"
#endif
/* Give default value if not defined */
#ifndef NET_IF_NUM
  #ifdef CONFIG_CONCURRENT_MODE
    #define NET_IF_NUM ((CONFIG_ETHERNET) + (CONFIG_WLAN) + 1)
  #else
    #define NET_IF_NUM ((CONFIG_ETHERNET) + (CONFIG_WLAN))
  #endif  // end of CONFIG_CONCURRENT_MODE
#endif  // end of NET_IF_NUM

/*Static IP ADDRESS*/
extern uint8_t sta_ip[], sta_gw[], sta_netmask[];

#ifndef IP_ADDR0
#define IP_ADDR0   sta_ip[0]
#define IP_ADDR1   sta_ip[1]
#define IP_ADDR2   sta_ip[2]
#define IP_ADDR3   sta_ip[3]
#endif

/*NETMASK*/
#ifndef NETMASK_ADDR0
#define NETMASK_ADDR0   sta_netmask[0]
#define NETMASK_ADDR1   sta_netmask[1]
#define NETMASK_ADDR2   sta_netmask[2]
#define NETMASK_ADDR3   sta_netmask[3]
#endif

/*Gateway Address*/
#ifndef GW_ADDR0
#define GW_ADDR0   sta_gw[0]
#define GW_ADDR1   sta_gw[1]
#define GW_ADDR2   sta_gw[2]
#define GW_ADDR3   sta_gw[3]
#endif

/*Static IP ADDRESS*/
#ifndef AP_IP_ADDR0
#define AP_IP_ADDR0   ap_ip[0]
#define AP_IP_ADDR1   ap_ip[1]
#define AP_IP_ADDR2   ap_ip[2]
#define AP_IP_ADDR3   ap_ip[3]
#endif
   
/*NETMASK*/
#ifndef AP_NETMASK_ADDR0
#define AP_NETMASK_ADDR0   ap_netmask[0]
#define AP_NETMASK_ADDR1   ap_netmask[1]
#define AP_NETMASK_ADDR2   ap_netmask[2]
#define AP_NETMASK_ADDR3   ap_netmask[3]
#endif

/*Gateway Address*/
#ifndef AP_GW_ADDR0
#define AP_GW_ADDR0   ap_gw[0]
#define AP_GW_ADDR1   ap_gw[1]
#define AP_GW_ADDR2   ap_gw[2]
#define AP_GW_ADDR3   ap_gw[3]
#endif

#define BSSID_LEN               17

enum {
	DHCP_MODE_DISABLE = 0,
	DHCP_MODE_ENABLE  = 1,
	DHCP_MODE_AS_CLIENT = DHCP_MODE_ENABLE,
	DHCP_MODE_AS_SERVER,
};
extern int dhcp_mode_sta;

enum {
	ESP_IPSTAT_UNKNOWN   = 0,
	ESP_IPSTAT_AP_AND_IP = 2,
	ESP_IPSTAT_CONN_CREATED,
	ESP_IPSTAT_DISCONN,
	ESP_IPSTAT_NO_AP,
};
int at_set_ipstatus(int esp_ipstat/* be enum value ESP_IPSTAT_XXX */);


int at_prt_lock_init(void);
unsigned at_prt_lock(void);
int at_prt_unlock(unsigned mask);

int at_bin2hex(u8* target, int tsz, const u8* src, int ssz, u8 delim);
int at_hex2bin(u8* target, int tsz, const u8* src, int ssz);

#define ATCMD_WIFI_CONN_STORE_MAX_NUM (1)
struct atcmd_wifi_conf{
	int32_t auto_enable;
	rtw_wifi_setting_t setting;
	int32_t reconn_num;
	int32_t reconn_last_index;	
	struct wlan_fast_reconnect reconn[ATCMD_WIFI_CONN_STORE_MAX_NUM];
};

#define ATCMD_LWIP_CONN_STORE_MAX_NUM (1)
struct atcmd_lwip_conn_info{
	int32_t role; //client, server or seed
	uint32_t protocol; //tcp or udp
	uint32_t remote_addr; //remote ip
	uint32_t remote_port; //remote port
	uint32_t local_addr; //locale ip, not used yet
	uint32_t local_port; //locale port, not used yet
	uint32_t reserved; //reserve for further use
};

struct atcmd_lwip_conf {
	int32_t enable; //enable or not
	int32_t conn_num;
	int32_t last_index;
	int32_t reserved; //reserve for further use
	struct atcmd_lwip_conn_info conn[ATCMD_LWIP_CONN_STORE_MAX_NUM];
};

typedef enum {
	AT_PARTITION_ALL = 0,
	AT_PARTITION_ATPORT = 1, /* UART/SPI settings */
	AT_PARTITION_WIFI = 2,
	AT_PARTITION_LWIP = 3
} AT_PARTITION;

typedef enum {
	AT_PARTITION_READ = 0,
	AT_PARTITION_WRITE = 1,
	AT_PARTITION_ERASE = 2
} AT_PARTITION_OP;

//first segment for uart/spi
#if !defined(ATPORT_SETTING_BACKUP_SECTOR)
#if defined(CONFIG_PLATFORM_8721D)
#define ATPORT_SETTING_BACKUP_SECTOR		(0x2000)
#else
#define ATPORT_SETTING_BACKUP_SECTOR		(0x8000)
#endif
#endif


//first segment for UART/SPI port setting
#define ATPORT_CONF_DATA_OFFSET			(0)
#define ATPORT_CONF_DATA_SIZE			(0x40)

//second segment for wifi config
#define WIFI_CONF_DATA_OFFSET			(ATPORT_CONF_DATA_OFFSET+ATPORT_CONF_DATA_SIZE)
#define WIFI_CONF_DATA_SIZE				((((sizeof(struct atcmd_wifi_conf)-1)>>2) + 1)<<2)

//fouth segment for lwip config
#define LWIP_CONF_DATA_OFFSET			(WIFI_CONF_DATA_OFFSET+WIFI_CONF_DATA_SIZE)
#define LWIP_CONF_DATA_SIZE				((((sizeof(struct atcmd_lwip_conf)-1)>>2) + 1)<<2)

int atcmd_wifi_restore_from_flash(void);
void atcmd_update_partition_info(AT_PARTITION id, AT_PARTITION_OP ops, u8 *data, u16 len);

#define ATSTRING_LEN 	(LOG_SERVICE_BUFLEN)
extern char at_string[ATSTRING_LEN];
extern unsigned char gAT_Echo; // default echo on





#if (defined(CONFIG_EXAMPLE_UART_ATCMD) && (CONFIG_EXAMPLE_UART_ATCMD))
typedef struct _UART_LOG_CONF_{
	u32 BaudRate;
	u8 DataBits;
	u8 StopBits;
	u8 Parity;
	u8 FlowControl;
}UART_LOG_CONF, *PUART_LOG_CONF;
// make sure the flash storage enough
extern char atport_conf_data_size_check [ATPORT_CONF_DATA_SIZE < sizeof(UART_LOG_CONF)? -1: 1];

extern void uart_at_send_buf(u8 *buf, u32 len);

#define at_printf(fmt, args...)  do{\
			/*uart_at_lock();*/\
			snprintf(at_string, ATSTRING_LEN, fmt, ##args); \
			uart_at_send_buf((u8*)at_string, strlen(at_string));\
			/*uart_at_unlock();*/\
	}while(0)
#define at_print_data(data, size)  do{\
			/*uart_at_lock();*/\
			uart_at_send_buf((u8*)data, size);\
			/*uart_at_unlock();*/\
	}while(0)





#elif (defined(CONFIG_EXAMPLE_SPI_ATCMD) && (CONFIG_EXAMPLE_SPI_ATCMD))

typedef struct _SPI_LOG_CONF_{
    int frequency;
    int bits;
    int mode;
}SPI_LOG_CONF, *PSPI_LOG_CONF;
// make sure the flash storage enough
extern char atport_conf_data_size_check [ATPORT_CONF_DATA_SIZE < sizeof(SPI_LOG_CONF)? -1: 1];


extern void spi_at_send_buf(u8 *buf, u32 len);

#define at_printf(fmt, args...)  do{       \
			unsigned m;        \
			m = at_prt_lock(); \
			snprintf(at_string, ATSTRING_LEN, fmt, ##args);    \
			spi_at_send_buf((u8*)at_string, strlen(at_string));\
			at_prt_unlock(m);  \
			/* printf(at_string); debug only*/                  \
	}while(0)
#define at_print_data(data, size)  do{\
			/*spi_at_lock();*/\
			spi_at_send_buf((u8*)data, size);\
			/*spi_at_unlock();*/\
	}while(0)





#else // #elif CONFIG_EXAMPLE_SPI_ATCMD
          
#define at_printf(fmt, args...) do{printf(fmt, ##args);}while(0)
#define at_print_data(data, size) do{__rtl_memDump(data, size, NULL);}while(0)
#endif//#if (defined(CONFIG_EXAMPLE_UART_ATCMD) && CONFIG_EXAMPLE_UART_ATCMD)


#if defined(configUSE_TRACE_FACILITY) && (configUSE_TRACE_FACILITY == 1)
int trace_task(void);
#endif


#if (defined(CONFIG_EXAMPLE_UART_ATCMD) && CONFIG_EXAMPLE_UART_ATCMD) || (defined(CONFIG_EXAMPLE_SPI_ATCMD) && CONFIG_EXAMPLE_SPI_ATCMD)
#define _EN_EXPORT_ATCMD 1
#else
#define _EN_EXPORT_ATCMD 0
#endif


#endif//__ATCMD_WIFI_H__

