#include <platform/platform_stdlib.h>
#include <platform_opts.h>

#include <stdio.h>
#include "log_service.h"
#include "atcmd_wifi.h"
#include "atcmd_lwip.h"
#include "osdep_service.h"
#include "lwip/dns.h"

#if defined(ATCMD_SUPPORT_SSL) && ATCMD_SUPPORT_SSL
#include "mbedtls/config.h"
#include "mbedtls/net.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) || \
	!defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
	!defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_NET_C) || \
	!defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)
#error ("some define missing, please check config_rsa.h")
#endif
#endif

#define MAX_BUFFER 		(TCP_MSS)
#define ATCP_STACK_SIZE		1024
#define ATCP_SSL_STACK_SIZE	2048


static unsigned char _tx_buffer[MAX_BUFFER + 1];
static unsigned char _rx_buffer[MAX_BUFFER + 1];
static unsigned char *tx_buffer = _tx_buffer;
static unsigned char *rx_buffer = _rx_buffer;
int tx_buffer_size = MAX_BUFFER;
int rx_buffer_size = MAX_BUFFER;

#if (CONFIG_EXAMPLE_SPI_ATCMD == 1)
#define EXTEND_ATPR_SIZE (1)
#endif

#if defined(EXTEND_ATPR_SIZE) && (EXTEND_ATPR_SIZE == 1)
#define FETCH_TIMEOUT         (3)
#define ATPR_RSVD_HEADER_SIZE (100)
#endif

#if CONFIG_LOG_SERVICE_LOCK
  #define LOG_SERVICE_LOCK log_service_lock
  #define LOG_SERVICE_UNLOCK log_service_unlock
#else
  #define LOG_SERVICE_LOCK() void
  #define LOG_SERVICE_UNLOCK() void
#endif

node node_pool[NUM_NS];

node *mainlist;

static int atcmd_lwip_auto_recv = FALSE;
volatile int atcmd_lwip_tt_mode = FALSE;	//transparent transmission mode
xTaskHandle atcmd_lwip_tt_task = NULL;
_sema atcmd_lwip_tt_sema = NULL;
volatile int atcmd_lwip_tt_datasize = 0;
volatile int atcmd_lwip_tt_lasttickcnt = 0;
const int esp_compatible_recv = TRUE;
const char* type2string(int type);
static node *_create_node(int mode, s8_t role, int prio);

#ifdef ERRNO
_WEAK int errno = 0;		//LWIP errno
#endif

#if defined(ATCMD_SUPPORT_SSL) && ATCMD_SUPPORT_SSL
#define ATCMD_SSL_DEBUG_LEVEL   0
static void atcmd_ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	if (level <= ATCMD_SSL_DEBUG_LEVEL) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "%s", str);
	}
}

static int atcmd_ssl_random(void *p_rng, unsigned char *output, size_t output_len)
{
	rtw_get_random_bytes(output, output_len);
	return 0;
}

static void *atcmd_ssl_malloc(size_t size)
{
	return (void *) rtw_malloc(size);
}

static void atcmd_ssl_free(void *p)
{
	rtw_mfree((u8 *) p, 0);
}

static void *my_calloc(size_t nelements, size_t elementSize)
{
	size_t size;
	void *ptr = NULL;

	size = nelements * elementSize;
	ptr = pvPortMalloc(size);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

static char *atcmd_lwip_itoa(int value)
{
	char *val_str;
	int tmp = value, len = 1;

	while ((tmp /= 10) > 0)
		len++;

	val_str = (char *) pvPortMalloc(len + 1);
	sprintf(val_str, "%d", value);

	return val_str;
}

/*********************************
* certificate and key for ssl server
*********************************/
static char *atcmd_ssl_server_crt[NUM_NS] = { NULL };	//TODO:should be input by user
static char *atcmd_ssl_server_ca_list[NUM_NS] = { NULL };	//TODO:should be input by user
static mbedtls_x509_crt *atcmd_ssl_srv_crt[NUM_NS] = { NULL };
static char *atcmd_ssl_server_key[NUM_NS] = { NULL };	//TODO:should be input by user
static mbedtls_pk_context *atcmd_ssl_srv_key[NUM_NS] = { NULL };

/*********************************
* certificate and key for ssl client
*********************************/
static char *atcmd_ssl_client_ca_crt[NUM_NS] = { NULL };	//TODO:should be input by user
static mbedtls_x509_crt *atcmd_ssl_cli_ca_crt[NUM_NS] = { NULL };
static char *atcmd_ssl_client_crt[NUM_NS] = { NULL };	//TODO:should be input by user
static mbedtls_x509_crt *atcmd_ssl_cli_crt[NUM_NS] = { NULL };
static char *atcmd_ssl_client_key[NUM_NS] = { NULL };	//TODO:should be input by user
static mbedtls_pk_context *atcmd_ssl_clikey_rsa[NUM_NS] = { NULL };
#endif				// defined(ATCMD_SUPPORT_SSL) && ATCMD_SUPPORT_SSL

int atcmd_lwip_start_autorecv_task(void);
int atcmd_lwip_start_tt_task(void);


int atcmd_lwip_is_tt_mode(void)
{
	return (atcmd_lwip_tt_mode == TRUE);
}

void atcmd_lwip_set_tt_mode(int enable)
{
	atcmd_lwip_tt_mode = enable;
}

int atcmd_lwip_is_autorecv_mode(void)
{
	return (atcmd_lwip_auto_recv == TRUE);
}

void atcmd_lwip_set_autorecv_mode(int enable)
{
	atcmd_lwip_auto_recv = enable;
}

static node *servernode = NULL;
static int  server_max_conn = NUM_NS - 2;

static void server_start(void *param)
{
	int s_mode;
	int s_sockfd, s_newsockfd;
	socklen_t s_client;
	struct sockaddr_in s_serv_addr, s_cli_addr;
	int s_local_port;
	int rt = 0;
	int s_opt = 1;
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	int ret;
	mbedtls_ssl_context *ssl;
	mbedtls_ssl_config *conf;
	mbedtls_net_context server_fd;
	mbedtls_x509_crt *server_x509;
	mbedtls_pk_context *server_pk;
#endif
	node *node_server = (node *) param;
	if (node_server) {
		s_mode = node_server->protocol;
		s_local_port = node_server->port;
	}

	/***********************************************************
	* Create socket and set socket options, then bind socket to local port
	************************************************************/
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (s_mode == NODE_MODE_SSL) {
		mbedtls_net_init(&server_fd);
		char *s_port_str = atcmd_lwip_itoa(s_local_port);
		if ((ret = mbedtls_net_bind(&server_fd, NULL, s_port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: net_bind %d\n", ret);
			rt = 15;
			goto err_exit;
		}
		s_sockfd = server_fd.fd;
		free(s_port_str);
	} else
#endif
	{
		if (s_mode == NODE_MODE_UDP)
			s_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		else if (s_mode == NODE_MODE_TCP)
			s_sockfd = socket(AF_INET, SOCK_STREAM, 0);
		else
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Unknown connection type[%d]", s_mode);

		if (s_sockfd == INVALID_SOCKET_ID) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR opening socket");
			rt = 5;
			goto err_exit;
		}

		if ((setsockopt(s_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &s_opt, sizeof(s_opt))) < 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR on setting socket option");
			close(s_sockfd);
			rt = 6;
			goto err_exit;
		}

		rtw_memset((char *) &s_serv_addr, 0, sizeof(s_serv_addr));
		s_serv_addr.sin_family = AF_INET;
		s_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		s_serv_addr.sin_port = htons(s_local_port);

		if (bind(s_sockfd, (struct sockaddr *) &s_serv_addr, sizeof(s_serv_addr)) < 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR on binding");
			close(s_sockfd);
			rt = 7;
			goto err_exit;
		}
	}

	/***********************************************************
	* Assign IP address and socket fd to the node used for this server
	************************************************************/
	if (node_server != NULL) {
		uint8_t *ip = (uint8_t *) LwIP_GetIP(&xnetif[0]);
		node_server->sockfd = s_sockfd;
		node_server->addr = ntohl(*((u32_t *) ip));
	}

	#if 0
	/* Wrong method, Server Node it self has no +LINK_CONN */
	if (esp_compatible_recv) {
		struct in_addr addr;
		addr.s_addr = htonl(node_server->addr);

		LOG_SERVICE_LOCK();
		at_set_ipstatus(ESP_IPSTAT_CONN_CREATED);

		at_printf("+LINK_CONN:%d,%d,\"%s\",%d,\"%s\",%d,%d\r\n",
			0, // Result code, 0 -- Success
			node_server->con_id,
			type2string(node_server->protocol),
			(node_server->role == NODE_ROLE_SERVER),
			inet_ntoa(addr),
			node_server->port,
			node_server->local_port
			);
		// at_printf(STR_RESP_OK);
		LOG_SERVICE_UNLOCK();
	}
	#endif

#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (s_mode == NODE_MODE_SSL) {
		/***********************************************************
		*  SSL 1. Prepare the certificate and key for ssl server
		************************************************************/
		char *srv_crt = NULL;
		char *ca_list = NULL;
		char *srv_key = NULL;
		atcmd_ssl_srv_crt[node_server->con_id] = (mbedtls_x509_crt *) rtw_zmalloc(sizeof(mbedtls_x509_crt));
		if (atcmd_ssl_srv_crt[node_server->con_id] == NULL) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl server crt");
			rt = 16;
			goto err_exit;
		}
		atcmd_ssl_srv_key[node_server->con_id] = (mbedtls_pk_context *) rtw_zmalloc(sizeof(mbedtls_pk_context));
		if (atcmd_ssl_srv_key[node_server->con_id] == NULL) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl server key");
			rt = 17;
			goto err_exit;
		}
		mbedtls_platform_set_calloc_free(my_calloc, vPortFree);
		server_x509 = atcmd_ssl_srv_crt[node_server->con_id];
		server_pk = atcmd_ssl_srv_key[node_server->con_id];

		mbedtls_x509_crt_init(server_x509);
		mbedtls_pk_init(server_pk);
		srv_crt = (atcmd_ssl_server_crt[node_server->con_id]) ? atcmd_ssl_server_crt[node_server->con_id] : (char *)
		    mbedtls_test_srv_crt;
		if ((ret = mbedtls_x509_crt_parse(server_x509, (const unsigned char *) srv_crt, strlen(srv_crt) + 1)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: x509_crt_parse server_x509/srv_crt %d\n", ret);
			rt = 18;
			goto err_exit;
		}
		ca_list = (atcmd_ssl_server_ca_list[node_server->con_id]) ? atcmd_ssl_server_ca_list[node_server->con_id] : (char *)
		    mbedtls_test_cas_pem;
		if ((ret = mbedtls_x509_crt_parse(server_x509, (const unsigned char *) ca_list, strlen(ca_list) + 1)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: x509_crt_parse server_x509/ca_list %d\n", ret);
			rt = 19;
			goto err_exit;
		}
		srv_key = (atcmd_ssl_server_key[node_server->con_id]) ? atcmd_ssl_server_key[node_server->con_id] : (char *)
		    mbedtls_test_srv_key;
		if ((ret = mbedtls_pk_parse_key(server_pk, srv_key, strlen(srv_key) + 1, NULL, 0)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: pk_parse_key server_pk %d\n", ret);
			rt = 20;
			goto err_exit;
		}
		/***********************************************************
		*  SSL 2. Hang node on mainlist for global management
		************************************************************/
		if (hang_node(node_server) < 0) {
			rt = 21;
			goto err_exit;
		} else {
			LOG_SERVICE_LOCK();
			at_printf("\r\n[ATPS] OK" "\r\n[ATPS] con_id=%d", node_server->con_id);
			at_printf(STR_END_OF_ATCMD_RET);
			LOG_SERVICE_UNLOCK();
		}
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "The SSL SERVER START OK!");
		/***********************************************************
		*  SSL 3. Waiting for ssl client to connect
		************************************************************/
		while (servernode) {
			//not using net_accept() here because it can't get client port in net_accept()
			if ((s_newsockfd = accept(s_sockfd, (struct sockaddr *) &s_cli_addr, &s_client)) < 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] ERROR:ERROR on net_accept ret=%d", ret);
				rt = 22;
				goto err_exit;
			}
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "An SSL/TLS client[%s:%d] is connecting",
				   inet_ntoa(s_cli_addr.sin_addr), ntohs(s_cli_addr.sin_port));
			/***********************************************************
			*  SSL 4. Setup stuff for this ssl connection
			************************************************************/
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Setting up the SSL/TLS structure...");
			ssl = (mbedtls_ssl_context *) rtw_malloc(sizeof(mbedtls_ssl_context));
			conf = (mbedtls_ssl_config *) rtw_zmalloc(sizeof(mbedtls_ssl_config));
			if ((ssl == NULL) || (conf == NULL)) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] malloc fail for ssl client context!");
				rt = 23;
				goto err_exit;
			}

			mbedtls_ssl_init(ssl);
			mbedtls_ssl_config_init(conf);

			if ((ret = mbedtls_ssl_config_defaults(conf,
							       MBEDTLS_SSL_IS_SERVER,
							       MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: ssl_config_defaults %d\n", ret);
				rt = 24;
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				goto err_exit;
			}

			mbedtls_ssl_conf_ca_chain(conf, server_x509->next, NULL);
			mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
			mbedtls_ssl_conf_rng(conf, atcmd_ssl_random, NULL);
			mbedtls_ssl_set_bio(ssl, &s_newsockfd, mbedtls_net_send, mbedtls_net_recv, NULL);
			if ((ret = mbedtls_ssl_conf_own_cert(conf, server_x509, server_pk)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: ssl_set_own_cert %d\n", ret);
				rt = 25;
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				goto err_exit;
			}

			if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: ssl_setup %d\n", ret);
				rt = 26;
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				goto err_exit;
			}
			/***********************************************************
			*  SSL 5. Wait for the ssl handshake done
			************************************************************/
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Performing the SSL/TLS handshake...");
			if ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: ssl_handshake -0x%x\n", -ret);
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				rt = 27;
				goto err_exit;
			}

			/***********************************************************
			*  SSL 6. Hang node on mainlist for global management
			************************************************************/
			node *seednode = _create_node(s_mode, NODE_ROLE_SEED, server_max_conn - 1);
			if (seednode == NULL) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS]create node failed!");
				rtw_free((void *) ssl);
				rt = 28;
				goto err_exit;
			}
			seednode->sockfd = s_newsockfd;
			seednode->port = ntohs(s_cli_addr.sin_port);
			seednode->addr = ntohl(s_cli_addr.sin_addr.s_addr);
			seednode->context = (void *) ssl;
			if (hang_seednode(node_server, seednode) < 0) {
				delete_node(seednode);
				seednode = NULL;
			} else {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "The SSL/TLS client is connected");
				LOG_SERVICE_LOCK();
				at_printf("\r\n[ATPS] A client connected to server[%d]\r\n"
					  "con_id:%d,"
					  "seed,"
					  "ssl,"
					  "address:%s,"
					  "port:%d,"
					  "socket:%d",
					  node_server->con_id,
					  seednode->con_id, inet_ntoa(s_cli_addr.sin_addr), ntohs(s_cli_addr.sin_port), seednode->sockfd);
				at_printf(STR_END_OF_ATCMD_RET);
				LOG_SERVICE_UNLOCK();
			}
		}
	} else
#endif				// #if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	{
		if (s_mode == NODE_MODE_TCP) {	//TCP MODE
			/***********************************************************
			*  TCP 1. Set this socket into listen mode
			************************************************************/
			if (listen(s_sockfd, 5) < 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR on listening");
				rt = 8;
				goto err_exit;
			}
			/***********************************************************
			*  TCP 2. Hang node on mainlist for global management
			************************************************************/
			if (param != NULL) {
				if (hang_node(node_server) < 0) {
					rt = 9;
					goto err_exit;
				} else {
					LOG_SERVICE_LOCK();
					if (esp_compatible_recv) {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "\r\n[ATPS] OK" "\r\n[ATPS] con_id=%d" STR_END_OF_ATCMD_RET, node_server->con_id);
					} else {
						at_printf("\r\n[ATPS] OK" "\r\n[ATPS] con_id=%d", node_server->con_id);
						at_printf(STR_END_OF_ATCMD_RET);
					}
					LOG_SERVICE_UNLOCK();
				}
			}

			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "The TCP SERVER START OK!");
			/***********************************************************
			*  TCP 3. Waiting for TCP client to connect
			************************************************************/
			while (servernode) {
				s_client = sizeof s_cli_addr;
				if ((s_newsockfd = accept(s_sockfd, (struct sockaddr *) &s_cli_addr, &s_client)) < 0) {
					if (param != NULL) {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
							"[ATPS] ERROR:ERROR on accept, errno = %d(%s)\r\n",
							errno, strerror(errno));
					}

					if (esp_compatible_recv) {
						rtw_msleep_os(10);
						continue;
					}
					rt = 10;
					goto err_exit;
				} else {
					/***********************************************************
					*  TCP 4. Hang node on mainlist for global management of this TCP connection
					************************************************************/
					if (param != NULL) {
						node *seednode = _create_node(s_mode, NODE_ROLE_SEED, server_max_conn - 1);
						if (seednode == NULL) {
							AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS]create node failed!");

							// we have to
							close(s_newsockfd);

							if (esp_compatible_recv) {
								continue;
							}
							rt = 11;
							goto err_exit;
						}
						seednode->sockfd = s_newsockfd;
						seednode->port = ntohs(s_cli_addr.sin_port);
						seednode->addr = ntohl(s_cli_addr.sin_addr.s_addr);
						if (hang_seednode(node_server, seednode) < 0) {
							delete_node(seednode);
							seednode = NULL;
						} else if (esp_compatible_recv) {
							LOG_SERVICE_LOCK();
							at_set_ipstatus(ESP_IPSTAT_CONN_CREATED);

							at_printf("+LINK_CONN:%d,%d,\"%s\",%d,\"%s\",%d,%d\r\n",
								0, // Result code, 0 -- Success
								seednode->con_id,
								type2string(seednode->protocol),
								// this SERVER received a new connection
								(seednode->role == NODE_ROLE_SEED),
								inet_ntoa(s_cli_addr.sin_addr.s_addr),
								ntohs(s_cli_addr.sin_port),
								seednode->local_port
							);
							LOG_SERVICE_UNLOCK();
						} else {
							LOG_SERVICE_LOCK();
							at_printf("\r\n[ATPS] A client connected to server[%d]\r\n"
								  "con_id:%d,"
								  "seed,"
								  "tcp,"
								  "address:%s,"
								  "port:%d,"
								  "socket:%d",
								  node_server->con_id,
								  seednode->con_id,
								  inet_ntoa(s_cli_addr.sin_addr.s_addr),
								  ntohs(s_cli_addr.sin_port), seednode->sockfd);
							at_printf(STR_END_OF_ATCMD_RET);
							LOG_SERVICE_UNLOCK();
						}
					}
				}
			}
		} else {
			/***********************************************************
			*  UDP 1. Enable broadcast on this socket 
			************************************************************/
#if IP_SOF_BROADCAST && IP_SOF_BROADCAST_RECV
			int so_broadcast = 1;
			if (setsockopt(s_sockfd, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast)) < 0) {
				rt = 14;
				goto err_exit;
			}
#endif
			/***********************************************************
			*  UDP 2. Hang node on mainlist for global management
			************************************************************/
			if (node_server != NULL) {
				if (hang_node(node_server) < 0) {
					rt = 12;
					goto err_exit;
				}
				LOG_SERVICE_LOCK();
				if (esp_compatible_recv) {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "\r\n[ATPS] OK" "\r\n[ATPS] con_id=%d" STR_END_OF_ATCMD_RET, node_server->con_id);
				} else {
					at_printf("\r\n[ATPS] OK" "\r\n[ATPS] con_id=%d", node_server->con_id);
					at_printf(STR_END_OF_ATCMD_RET);
				}
				LOG_SERVICE_UNLOCK();
				//task will exit itself
				node_server->handletask = NULL;
			}
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "The UDP SERVER START OK!");
		}
	}

err_exit:
	if (!servernode && node_server) {
		//task will exit itself if getting here
		node_server->handletask = NULL;
		delete_node(node_server);
	}
	LOG_SERVICE_LOCK();
	if (esp_compatible_recv) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "\r\n[ATPS] ERROR:%d" STR_END_OF_ATCMD_RET, rt);
	} else {
		at_printf("\r\n[ATPS] ERROR:%d", rt);
		at_printf(STR_END_OF_ATCMD_RET);
	}
	LOG_SERVICE_UNLOCK();
exit:
	return;
}

static void client_start(void *param)
{
	int c_mode;
	int c_remote_port;
	char c_remote_addr[16];
	int c_sockfd;
	struct sockaddr_in c_serv_addr;
	int rt = 0;
#if ATCMD_SUPPORT_SSL
	int ret;
	mbedtls_ssl_context *ssl;
	mbedtls_ssl_config *conf;
	mbedtls_net_context server_fd;
#endif
	node *node_client = (node *) param;
	if (node_client) {
		struct in_addr c_addr;
		c_mode = node_client->protocol;
		c_remote_port = node_client->port;
		c_addr.s_addr = htonl(node_client->addr);
		if (inet_ntoa_r(c_addr, c_remote_addr, sizeof(c_remote_addr)) == NULL) {
			rt = 6;
			goto err_exit;
		}
	}

	/***********************************************************
	* Create socket and set socket options, then bind socket to local port
	************************************************************/
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (c_mode == NODE_MODE_SSL) {
		mbedtls_net_init(&server_fd);
		char *c_port_str = atcmd_lwip_itoa(c_remote_port);
		if ((ret = mbedtls_net_connect(&server_fd, c_remote_addr, c_port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Failed to create sock_fd!ret=%d", ret);
			rt = 18;
			goto err_exit;
		}
		c_sockfd = server_fd.fd;
		free(c_port_str);
	} else
#endif
	{
		if (c_mode == NODE_MODE_UDP)
			c_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		else if (c_mode == NODE_MODE_TCP)
			c_sockfd = socket(AF_INET, SOCK_STREAM, 0);
		else
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Unknown connection type[%d]", c_mode);
		if (c_sockfd == INVALID_SOCKET_ID) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Failed to create sock_fd!");
			rt = 7;
			goto err_exit;
		}
		rtw_memset(&c_serv_addr, 0, sizeof(c_serv_addr));
		c_serv_addr.sin_family = AF_INET;
		c_serv_addr.sin_addr.s_addr = inet_addr(c_remote_addr);
		c_serv_addr.sin_port = htons(c_remote_port);
	}
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "OK to create sock_fd!");

	/***********************************************************
	* Assign socket fd to the node used for this client
	************************************************************/
	if (node_client) {
		node_client->sockfd = c_sockfd;
	}
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (c_mode == NODE_MODE_SSL) {	//SSL MODE
		/***********************************************************
		*  SSL 1. Setup stuff for this ssl connection
		************************************************************/
		int retry_count = 0;
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Setting up the SSL/TLS structure...");
		mbedtls_platform_set_calloc_free(my_calloc, vPortFree);
		ssl = (mbedtls_ssl_context *) rtw_zmalloc(sizeof(mbedtls_ssl_context));
		conf = (mbedtls_ssl_config *) rtw_zmalloc(sizeof(mbedtls_ssl_config));
		if ((ssl == NULL) || (conf == NULL)) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl");
			rt = 19;
			goto err_exit;
		}
		node_client->context = (void *) ssl;

		mbedtls_ssl_init(ssl);
		mbedtls_ssl_config_init(conf);


		if ((ret = mbedtls_ssl_config_defaults(conf,
						       MBEDTLS_SSL_IS_CLIENT,
						       MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl");
			rt = 20;
			rtw_free((void *) ssl);
			rtw_free((void *) conf);
			goto err_exit;
		}

		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_rng(conf, atcmd_ssl_random, NULL);
		mbedtls_ssl_set_bio(ssl, &node_client->sockfd, mbedtls_net_send, mbedtls_net_recv, NULL);
		mbedtls_ssl_conf_dbg(conf, atcmd_ssl_debug, NULL);

		if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl");
			rt = 21;
			rtw_free((void *) ssl);
			rtw_free((void *) conf);
			goto err_exit;
		}
#ifdef MBEDTLS_DEBUG_C
		mbedtls_debug_set_threshold(ATCMD_SSL_DEBUG_LEVEL);
#endif
		/***********************************************************
		*  SSL 2. Wait for the ssl handshake done
		************************************************************/
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Performing the SSL/TLS handshake...");
		while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
			if (retry_count >= 5) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ssl_handshake failed -0x%x\n", -ret);
				rt = 22;
				goto err_exit;
			}
			retry_count++;
		}
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Connect to Server successful!");
		/***********************************************************
		*  SSL 3. Hang node on mainlist for global management
		************************************************************/
		if (hang_node(node_client) < 0) {
			rt = 23;
			goto err_exit;
		}
		LOG_SERVICE_LOCK();
		at_printf("\r\n[ATPC] OK\r\n[ATPC] con_id=%d", node_client->con_id);
		at_printf(STR_END_OF_ATCMD_RET);
		LOG_SERVICE_UNLOCK();
	} else
#endif				//#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	{
		if (c_mode == NODE_MODE_TCP) {	//TCP MODE
			/***********************************************************
			*  TCP 1. Connect a netconn to a specific remote IP address and port
			************************************************************/
			if (connect(c_sockfd, (struct sockaddr *) &c_serv_addr, sizeof(c_serv_addr)) == 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Connect to Server successful!");
				/***********************************************************
				*  TCP 2. Hand node on mainlist for global management if connect success
				************************************************************/
				if (node_client != NULL) {
					if (hang_node(node_client) < 0) {
						rt = 8;
						goto err_exit;
					}
					LOG_SERVICE_LOCK();
					at_printf("\r\n[ATPC] OK\r\n[ATPC] con_id=%d", node_client->con_id);
					at_printf(STR_END_OF_ATCMD_RET);
					LOG_SERVICE_UNLOCK();
				}
			} else {
				/***********************************************************
				*  TCP 2. Free node if connect fail
				************************************************************/
				if (node_client != NULL) {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] ERROR:Connect to Server failed!");
				}
				rt = 9;
				goto err_exit;
			}
		} else {
			if (node_client != NULL) {
#if IP_SOF_BROADCAST && IP_SOF_BROADCAST_RECV
				/* all ones (broadcast) or all zeroes (old skool broadcast) */
				if ((c_serv_addr.sin_addr.s_addr == htonl(INADDR_BROADCAST)) ||
				    (c_serv_addr.sin_addr.s_addr == htonl(INADDR_ANY))) {
					int so_broadcast = 1;
					if (setsockopt(c_sockfd, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast)) < 0) {
						rt = 14;
						goto err_exit;
					}
				}
#endif
#if LWIP_IGMP
				ip_addr_t dst_addr;
				dst_addr.addr = c_serv_addr.sin_addr.s_addr;
				if (ip_addr_ismulticast(&dst_addr)) {
					struct ip_mreq imr;
					struct in_addr intfAddr;
					// Set NETIF_FLAG_IGMP flag for netif which should process IGMP messages
					xnetif[0].flags |= NETIF_FLAG_IGMP;
					imr.imr_multiaddr.s_addr = c_serv_addr.sin_addr.s_addr;
					imr.imr_interface.s_addr = INADDR_ANY;
					if (setsockopt(c_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr)) < 0) {
						xnetif[0].flags &= ~NETIF_FLAG_IGMP;
						rt = 15;
						goto err_exit;
					}
					intfAddr.s_addr = INADDR_ANY;
					if (setsockopt(c_sockfd, IPPROTO_IP, IP_MULTICAST_IF, &intfAddr, sizeof(struct in_addr)) < 0) {
						xnetif[0].flags &= ~NETIF_FLAG_IGMP;
						rt = 16;
						goto err_exit;
					}
				}
#endif
				if (node_client->local_port) {
					struct sockaddr_in addr;
					rtw_memset(&addr, 0, sizeof(addr));
					addr.sin_family = AF_INET;
					addr.sin_port = htons(node_client->local_port);
					addr.sin_addr.s_addr = htonl(INADDR_ANY);
					if (bind(node_client->sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "bind sock error!");
						rt = 12;
						goto err_exit;
					}
				}
				if (hang_node(node_client) < 0) {
					rt = 10;
					goto err_exit;
				}
				LOG_SERVICE_LOCK();
				at_printf("\r\n[ATPC] OK\r\n[ATPC] con_id=%d", node_client->con_id);
				at_printf(STR_END_OF_ATCMD_RET);
				LOG_SERVICE_UNLOCK();
			}
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "UDP client starts successful!");
		}
	}
	goto exit;
      err_exit:
	if (node_client) {
		delete_node(node_client);
	}
	LOG_SERVICE_LOCK();
	at_printf("\r\n[ATPC] ERROR:%d", rt);
	at_printf(STR_END_OF_ATCMD_RET);
	LOG_SERVICE_UNLOCK();
      exit:
	return;
}

static void client_start_task(void *param)
{
	vTaskDelay(1000);
	if (param) {
		client_start(param);
	}
	vTaskDelete(NULL);
	return;
}

/* Sync the sequence of task server_send_task and parent task */
static _sema server_started, server_ok_sync;

static void server_start_task(void *param)
{
	if (esp_compatible_recv) {
		rtw_init_sema(&server_ok_sync, 0);

		// tell parent task we had started.
		rtw_up_sema(&server_started);

		// Wait for parent task sent "OK"
		rtw_down_sema(&server_ok_sync);

		rtw_free_sema(&server_ok_sync);
	}

	vTaskDelay(1000);


	if (param != NULL) {
		server_start(param);
	}
	vTaskDelete(NULL);
	return;
}

//AT Command function
void fATP0(void *arg)
{
	(void) arg;
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATP0]: _AT_TRANSPORT_ERRNO");
#ifdef ERRNO
	at_printf("\r\n[ATP0] OK:%d", errno);
#else
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "errno isn't enabled");
	at_printf("\r\n[ATP0] ERROR");
#endif
}

void fATPC(void *arg)
{
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	node *clientnode = NULL;
	int mode = 0;
	int remote_port;
	int local_port = 0;
	//char remote_addr[DNS_MAX_NAME_LENGTH];
	struct in_addr addr;
	int rt = 0;
	u32 client_task_stksz = ATCP_STACK_SIZE;
#if LWIP_DNS
	struct hostent *server_host;
#endif

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPC]: _AT_TRANSPORT_START_CLIENT");

	if (atcmd_lwip_is_tt_mode() && mainlist->next) {
		rt = 13;
		goto err_exit;
	}

	argc = parse_param(arg, argv);
	if (argc < 4) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
			   "[ATPC] Usage: ATPC=<TCP:0/UDP:1/SSL:2>,<REMOTE_IP>,<REMOTE_Port(1~65535)>,[<LOCAL_PORT>]");
		rt = 1;
		goto err_exit;
	}

	mode = atoi((char *) argv[1]);	//tcp, udp or ssl
	if (mode != NODE_MODE_TCP && mode != NODE_MODE_UDP && mode != NODE_MODE_SSL) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] Unknown connection type[%d]", mode);
		rt = 17;
		goto err_exit;
	}

	remote_port = atoi((char *) argv[3]);
	if (inet_aton(argv[2], &addr) == 0) {
#if LWIP_DNS
		server_host = gethostbyname(argv[2]);
		if (server_host) {
			rtw_memcpy(&addr, server_host->h_addr, 4);
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPC] Found name '%s' = %s", argv[2], inet_ntoa(addr)
			    );
		} else
#endif
		{
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] ERROR: Host '%s' not found.", argv[2]);
			rt = 2;
			goto err_exit;
		}
	}

	if (remote_port < 0 || remote_port > 65535) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] ERROR: remote port invalid");
		rt = 3;
		goto err_exit;
	}

	if (argv[4]) {
		local_port = atoi((char *) argv[4]);
		if (local_port < 0 || local_port > 65535) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] ERROR: local port invalid");
			rt = 11;
			goto err_exit;
		}
	}

	clientnode = create_node(mode, NODE_ROLE_CLIENT);
	if (clientnode == NULL) {
		rt = 4;
		goto err_exit;
	}
	clientnode->port = remote_port;
	clientnode->addr = ntohl(addr.s_addr);
	clientnode->local_port = local_port;
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (mode == NODE_MODE_SSL)
		client_task_stksz = ATCP_SSL_STACK_SIZE;
#endif
	if (xTaskCreate
	    (client_start_task, ((const char *) "client_start_task"), client_task_stksz, clientnode,
	     ATCMD_LWIP_TASK_PRIORITY, NULL) != pdPASS) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPC] ERROR: Create tcp/udp/ssl client task failed.");
		rt = 5;
		goto err_exit;
	}

	goto exit;
      err_exit:
	if (clientnode)
		delete_node(clientnode);
	at_printf("\r\n[ATPC] ERROR:%d", rt);
      exit:
	return;
}


void fATPS(void *arg)
{
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int mode;
	int local_port;
	int rt = 0;
	u32 server_task_stksz = ATCP_STACK_SIZE;

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPS]: _AT_TRANSPORT_START_SERVER");

	if (atcmd_lwip_is_tt_mode()) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] ERROR: Server can only start when TT is disabled");
		rt = 13;
		goto err_exit;
	}

	argc = parse_param(arg, argv);
	if (argc != 3) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] Usage: ATPS=[TCP:0/UDP:1/SSL:2],[Local port(1~65535)]");
		rt = 1;
		goto err_exit;
	}

	mode = atoi((char *) argv[1]);
	if (mode != NODE_MODE_TCP && mode != NODE_MODE_UDP && mode != NODE_MODE_SSL) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] Unknown connection type[%d]", mode);
		rt = 15;
		goto err_exit;
	}

	local_port = atoi((char *) argv[2]);
	if (local_port < 0 || local_port > 65535) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] Usage: ATPS=[TCP:0/UDP:1/SSL:2],[Local port]");
		rt = 2;
		goto err_exit;
	}

	servernode = create_node(mode, NODE_ROLE_SERVER);
	if (servernode == NULL) {
		rt = 3;
		goto err_exit;
	}
	servernode->port = local_port;

	if (mode == NODE_MODE_SSL)
		server_task_stksz = ATCP_SSL_STACK_SIZE;

	if (xTaskCreate
	    (server_start_task, ((const char *) "server_start_task"), server_task_stksz, servernode,
	     ATCMD_LWIP_TASK_PRIORITY, &servernode->handletask) != pdPASS) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPS] ERROR: Create tcp/udp/ssl server task failed.");
		rt = 4;
		goto err_exit;
	}

	goto exit;
      err_exit:
	if (servernode) {
		delete_node(servernode);
		servernode = NULL;
	}
	at_printf("\r\n[ATPS] ERROR:%d", rt);
      exit:
	return;
}

void socket_close_all(void)
{
	node *cn = mainlist->next;

	while (cn) {
		delete_node(cn);
		cn = mainlist->next;
	}
	cn = NULL;
}

void fATPD(void *arg)
{
	int con_id = INVALID_CON_ID;
	int rt = 0;
	node *s_node;

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPD]: _AT_TRANSPORT_CLOSE_CONNECTION");

	if (!arg) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPD] Usage: ATPD=con_id or 0 (close all)");
		rt = 1;
		goto exit;
	}
	con_id = atoi((char *) arg);

	if (con_id == INVALID_CON_ID) {
		if (atcmd_lwip_is_autorecv_mode()) {
			atcmd_lwip_set_autorecv_mode(FALSE);
		}
		socket_close_all();
		goto exit;
	}

	s_node = seek_node(con_id);
	if (s_node == NULL) {
		rt = 3;
		goto exit;
	}
	delete_node(s_node);

exit:
	s_node = NULL;
	if (rt)
		at_printf("\r\n[ATPD] ERROR:%d", rt);
	else
		at_printf("\r\n[ATPD] OK");
	return;
}

int atcmd_lwip_send_data(node * cn, u8 * data, u16 data_sz, struct sockaddr_in cli_addr)
{
	int rt = 0;

	if ((cn->protocol == NODE_MODE_UDP) && (cn->role == NODE_ROLE_SERVER)) { //UDP server
		if (sendto(cn->sockfd, data, data_sz, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) <= 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPT] ERROR:Failed to send data");
			rt = 5;
		}
	} else {
		if (cn->protocol == NODE_MODE_UDP) { //UDP client/seed
			struct sockaddr_in serv_addr;
			rtw_memset(&serv_addr, 0, sizeof(serv_addr));
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(cn->port);
			serv_addr.sin_addr.s_addr = htonl(cn->addr);
			if (sendto(cn->sockfd, data, data_sz, 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) <= 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPT] ERROR:Failed to send data\n");
				rt = 6;
			}
		} else
		if ((cn->protocol == NODE_MODE_TCP) || (cn->protocol == NODE_MODE_SSL)) { //TCP or SSL
			int ret;

			if (cn->role == NODE_ROLE_SERVER) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPT] ERROR: TCP Server must send data to the seed");
				rt = -EINVAL;
				goto exit;
			}

			#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
			if (cn->protocol == NODE_MODE_SSL) {
				ret = mbedtls_ssl_write((mbedtls_ssl_context *) cn->context, data, data_sz);
			} else
			#endif
			{
				ret = write(cn->sockfd, data, data_sz);
			}
			if (ret <= 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPT] ERROR:Failed to send data %d", ret);
				rt = 8;
			}
		}
	}

      exit:
	return rt;
}

void fATPT(void *arg)
{
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int con_id = INVALID_CON_ID;
	int rt = 0;
	node *cn = NULL;
	struct sockaddr_in cli_addr;
	int data_sz;
	int data_pos = C_NUM_AT_CMD + C_NUM_AT_CMD_DLT + strlen(arg) + 1;
	u8 *data = (u8 *) log_buf + data_pos;

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPT]: _AT_TRANSPORT_SEND_DATA");

	argc = parse_param(arg, argv);

	if (argc != 3 && argc != 5) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
			   "[ATPT] Usage: ATPT=<data_size>,"
			   "<con_id>[,<dst_ip>,<dst_port>]" ":<data>(MAX %d)", MAX_BUFFER);
		rt = 1;
		goto exit;
	}

	data_sz = atoi((char *) argv[1]);
	if (data_sz > MAX_BUFFER) {
		rt = 2;
		goto exit;
	}

	con_id = atoi((char *) argv[2]);
	cn = seek_node(con_id);
	if (cn == NULL) {
		rt = 3;
		goto exit;
	}

	if ((cn->protocol == NODE_MODE_UDP)
	    && (cn->role == NODE_ROLE_SERVER)) {
		char udp_clientaddr[16] = { 0 };
		strcpy((char *) udp_clientaddr, (char *) argv[3]);
		cli_addr.sin_family = AF_INET;
		cli_addr.sin_port = htons(atoi((char *) argv[4]));
		if (inet_aton(udp_clientaddr, &cli_addr.sin_addr) == 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPT]ERROR:inet_aton() failed");
			rt = 4;
			goto exit;
		}
	}
	rt = atcmd_lwip_send_data(cn, data, data_sz, cli_addr);
      exit:
	if (rt)
		at_printf("\r\n[ATPT] ERROR:%d,%d", rt, con_id);
	else
		at_printf("\r\n[ATPT] OK,%d", con_id);
	return;
}

void fATPR(void *arg)
{
	int argc, con_id = INVALID_CON_ID;
	char *argv[MAX_ARGC] = { 0 };
	int rt = 0;
	int recv_size = 0;
	int packet_size = 0;
	node *cn = NULL;
	u8_t udp_clientaddr[16] = { 0 };
	u16_t udp_clientport = 0;

#if defined(EXTEND_ATPR_SIZE) && (EXTEND_ATPR_SIZE == 1)
	int total_recv_size = 0;
	int next_expected_size = 0;
	int fetch_counter = 0;
	char tmpbuf[ATPR_RSVD_HEADER_SIZE];
	int header_len = 0;
#endif

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPR]: _AT_TRANSPORT_RECEIVE_DATA");

	if (atcmd_lwip_is_autorecv_mode()) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR: Receive changed to auto mode.");
		rt = 10;
		goto exit;
	}

	argc = parse_param(arg, argv);
	if (argc != 3) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] Usage: ATPR =<con_id>,<Buffer Size>\n\r");
		rt = 1;
		goto exit;
	}

	con_id = atoi((char *) argv[1]);
	if (con_id <= 0 || con_id > NUM_NS) {
		rt = 9;
		goto exit;
	}

	packet_size = atoi((char *) argv[2]);

	if (packet_size <= 0
#if defined(EXTEND_ATPR_SIZE) && (EXTEND_ATPR_SIZE==1)
	    || packet_size > ((rx_buffer_size > MAX_BUFFER) ? rx_buffer_size : MAX_BUFFER)
#else
	    || packet_size > MAX_BUFFER
#endif
	    ) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] Recv Size(%d) exceeds MAX_BUFFER(%d)", packet_size, MAX_BUFFER);
		rt = 2;
		goto exit;
	}

	cn = seek_node(con_id);
	if (cn == NULL) {
		rt = 3;
		goto exit;
	}

	if (cn->protocol == NODE_MODE_TCP && cn->role == NODE_ROLE_SERVER) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR: TCP Server must receive data from the seed");
		rt = 6;
		goto exit;
	}

	memset(rx_buffer, 0, rx_buffer_size);
	int r = atcmd_lwip_receive_data(cn, rx_buffer, rx_buffer_size, &recv_size, udp_clientaddr, &udp_clientport);
	if (r < 0) rt = 7;

      exit:
	if (rt == 0) {
#if defined(EXTEND_ATPR_SIZE) && (EXTEND_ATPR_SIZE == 1)
		total_recv_size = recv_size;
		fetch_counter = 0;
		while (total_recv_size < packet_size - ATPR_RSVD_HEADER_SIZE) {	// 100 is reserved for the AT command header
			next_expected_size = packet_size - total_recv_size - ATPR_RSVD_HEADER_SIZE;
			if (next_expected_size > ETH_MAX_MTU) {
				next_expected_size = ETH_MAX_MTU;
			}
			r = atcmd_lwip_receive_data(cn, rx_buffer + total_recv_size, next_expected_size,
						    &recv_size, udp_clientaddr, &udp_clientport);
			fetch_counter = (recv_size == 0) ? (fetch_counter + 1) : 0;
			if (fetch_counter >= FETCH_TIMEOUT) {
				break;
			}
			total_recv_size += recv_size;
			if (r < 0) {
				break;
			}
		}
		memset(tmpbuf, 0, ATPR_RSVD_HEADER_SIZE);
		if (cn->protocol == NODE_MODE_UDP && cn->role == NODE_ROLE_SERVER) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO,
				   "\r\n[ATPR] OK,%d,%d,%s,%d:%s", total_recv_size, con_id, udp_clientaddr, udp_clientport, rx_buffer);
			sprintf(tmpbuf, "\r\n[ATPR] OK,%d,%d,%s,%d:", total_recv_size, con_id, udp_clientaddr, udp_clientport);
		} else {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "\r\n[ATPR] OK,%d,%d:%s", total_recv_size, con_id, rx_buffer);
			sprintf(tmpbuf, "\r\n[ATPR] OK,%d,%d:", total_recv_size, con_id);
		}
		header_len = strlen(tmpbuf);
		memmove(rx_buffer + header_len, rx_buffer, total_recv_size);
		memcpy(rx_buffer, tmpbuf, header_len);
		at_print_data(rx_buffer, total_recv_size + header_len);
#else				// #if (EXTEND_ATPR_SIZE)
		if (cn->protocol == NODE_MODE_UDP && cn->role == NODE_ROLE_SERVER) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO,
				   "\r\n[ATPR] OK,%d,%d,%s,%d:%s", recv_size, con_id, udp_clientaddr, udp_clientport, rx_buffer);
			at_printf("\r\n[ATPR] OK,%d,%d,%s,%d:", recv_size, con_id, udp_clientaddr, udp_clientport);
		} else {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "\r\n[ATPR] OK,%d,%d:%s", recv_size, con_id, rx_buffer);
			at_printf("\r\n[ATPR] OK,%d,%d:", recv_size, con_id);
		}
		if (recv_size)
			at_print_data(rx_buffer, recv_size);
#endif // #if (EXTEND_ATPR_SIZE)
	} else
		at_printf("\r\n[ATPR] ERROR:%d,%d", rt, con_id);
	return;
}

void fATPK(void *arg)
{
	int argc;
	int rt = 0;
	int enable = 0;
	char *argv[MAX_ARGC] = { 0 };

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPK]: _AT_TRANSPORT_AUTO_RECV");

	argc = parse_param(arg, argv);
	if (argc < 2) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPK] Usage: ATPK=<0/1>\n\r");
		rt = 1;
		goto exit;
	}

	enable = atoi((char *) argv[1]);

	if (enable) {
		if (atcmd_lwip_is_autorecv_mode()) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPK] already enter auto receive mode");
		} else {
			if (atcmd_lwip_start_autorecv_task())
				rt = 2;
		}
	} else {
		if (atcmd_lwip_is_autorecv_mode())
			atcmd_lwip_set_autorecv_mode(FALSE);
		else {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPK] already leave auto receive mode");
		}
	}

      exit:
	if (rt)
		at_printf("\r\n[ATPK] ERROR:%d", rt);
	else
		at_printf("\r\n[ATPK] OK");
	return;
}

void fATPU(void *arg)
{

	int argc;
	int rt = 0;
	int enable = 0;
	char *argv[MAX_ARGC] = { 0 };

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPU]: _AT_TRANSPORT_TT_MODE");

	argc = parse_param(arg, argv);
	if (argc < 2) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPU] Usage: ATPU=<1>\n\r");
		rt = 1;
		goto exit;
	}

	enable = atoi((char *) argv[1]);

	if (enable) {
		if (!mainlist->next) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPU] No conn found");
			rt = 2;
		} else if (mainlist->next->role == NODE_ROLE_SERVER) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPU] No TT mode for server");
			rt = 3;
		} else if (mainlist->next->next || mainlist->next->nextseed) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPU] More than one conn found");
			rt = 4;
		} else {
			if (atcmd_lwip_start_tt_task()) {
				rt = 5;
			}
		}
	}

      exit:
	if (rt)
		at_printf("\r\n[ATPU] ERROR:%d", rt);
	else
		at_printf("\r\n[ATPU] OK");
	return;
}

//ATPL=<enable>
void fATPL(void *arg)
{
	int argc, rt = 0;
	char *argv[MAX_ARGC] = { 0 };

	if (!arg) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "\r\n[ATPL] Usage : ATPL=<enable>");
		rt = 1;
		goto exit;
	}
	argc = parse_param(arg, argv);
	if (argc != 2) {
		rt = 2;
		goto exit;
	}
	//ENABLE LWIP FAST CONNECT
	if (argv[1] != NULL) {
		int enable = atoi(argv[1]);
		struct atcmd_lwip_conn_info cur_conn = { 0 };
		node *cn = mainlist->next;
		if (enable && cn == NULL) {
			rt = 3;
			goto exit;
		}
		cur_conn.role = cn->role;
		cur_conn.protocol = cn->protocol;
		cur_conn.remote_addr = cn->addr;
		cur_conn.remote_port = cn->port;
		cur_conn.local_addr = cn->local_addr;
		cur_conn.local_port = cn->local_port;
		atcmd_lwip_write_info_to_flash(&cur_conn, enable);
	}

      exit:
	if (rt == 0)
		at_printf("\r\n[ATPL] OK");
	else
		at_printf("\r\n[ATPL] ERROR:%d", rt);

	return;
}

extern void do_ping_call(char *ip, int loop, int count);
extern int get_ping_report(int *ping_lost);
void fATPP(void *arg)
{
	int count, argc = 0;
	char buf[32] = { 0 };
	char *argv[MAX_ARGC] = { 0 };
	int con_id = INVALID_CON_ID;
	int rt = 0;
	int ping_lost = 0;

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPP]: _AT_TRANSPORT_PING");

	if (!arg) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
			   "[ATPP] Usage: ATPP=xxxx.xxxx.xxxx.xxxx[y/loop] or ATPP=[con_id],[y/loop]\n\r");
		rt = 1;
		goto exit;
	}

	argc = parse_param(arg, argv);

	if (strlen(argv[1]) < 3) {
		node *cn;
		struct in_addr addr;
		con_id = atoi((char *) argv[1]);
		cn = seek_node(con_id);
		if (cn == NULL) {
			rt = 2;
			goto exit;
		}
		if (cn->role == 1) {	//ping remote server
			addr.s_addr = htonl(cn->addr);
			inet_ntoa_r(addr, buf, sizeof(buf));
		} else if (cn->role == 0) {	//ping local server
			strcpy(buf, SERVER);
		} else if (cn->role == 2) {	//ping seed
			strcpy(buf, (char *) cn->addr);
		}
	} else
		strcpy(buf, argv[1]);

	if (argc == 2) {
		count = 5;
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPP]Repeat Count: %d", count);
		do_ping_call(buf, 0, count);	//Not loop, count=5
	} else {
		if (strcmp(argv[2], "loop") == 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPP]Repeat Count: %s", "loop");
			do_ping_call(buf, 1, 0);	//loop, no count
		} else {
			count = atoi(argv[2]);
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPP]Repeat Count: %d", count);
			do_ping_call(buf, 0, count);	//Not loop, with count
		}
	}

	get_ping_report(&ping_lost);
	if (ping_lost)
		rt = (ping_lost == count) ? 4 : 3;	// 3: partially lost, 4: totally lost

      exit:
	if (rt)
		at_printf("\r\n[ATPP] ERROR:%d", rt);
	else
		at_printf("\r\n[ATPP] OK");
	return;
}

void fATPI(void *arg)
{
	node *n = mainlist->next;
	struct in_addr addr;

	(void) arg;
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "[ATPI]: _AT_TRANSPORT_CONNECTION_INFO");

	while (n != NULL) {
		if (n->con_id == INVALID_CON_ID)
			continue;

		at_printf("\r\ncon_id:%d,", n->con_id);

		if (n->role == NODE_ROLE_SERVER)
			at_printf("server,");
		else
			at_printf("client,");
		if (n->protocol == NODE_MODE_TCP)
			at_printf("tcp,");
		else if (n->protocol == NODE_MODE_SSL)
			at_printf("ssl,");
		else
			at_printf("udp,");

		addr.s_addr = htonl(n->addr);
		at_printf("address:%s,port:%d,socket:%d", inet_ntoa(addr), n->port, n->sockfd);
		if (n->nextseed != NULL) {
			node *seed = n;
			do {
				seed = seed->nextseed;
				at_printf("\r\ncon_id:%d,seed,", seed->con_id);
				if (seed->protocol == NODE_MODE_TCP)
					at_printf("tcp,");
				else if (n->protocol == NODE_MODE_SSL)
					at_printf("ssl,");
				else
					at_printf("udp,");
				addr.s_addr = htonl(seed->addr);
				at_printf("address:%s,port:%d,socket:%d", inet_ntoa(addr), seed->port, seed->sockfd);
			} while (seed->nextseed != NULL);
		}
		n = n->next;
	}

	at_printf("\r\n[ATPI] OK");

	return;
}

void init_node_pool(void)
{
	int i;
	rtw_memset(node_pool, 0, sizeof(node_pool));
	for (i = 0; i < NUM_NS; i++) {
		node_pool[i].con_id = INVALID_CON_ID;
	}
}

/*
 * argument prio for esp compatible
 * try # prio firstly.
 */
static node *_create_node(int mode, s8_t role, int prio)
{
	int i, depth;

	SYS_ARCH_DECL_PROTECT(lev);

	i = prio < 0 ? 0 : prio;
	for (depth = NUM_NS; depth > 0; depth--) {
		SYS_ARCH_PROTECT(lev);
		if (node_pool[i].con_id == INVALID_CON_ID) {
			node_pool[i].con_id = i;
			SYS_ARCH_UNPROTECT(lev);
			node_pool[i].sockfd = INVALID_SOCKET_ID;
			node_pool[i].protocol = mode;	// 0:TCP, 1:UDP
			node_pool[i].role = role;	// 0:server, 1:client, 2:SEED
			node_pool[i].addr = 0;
			node_pool[i].port = -1;
			node_pool[i].handletask = NULL;
			node_pool[i].next = NULL;
			node_pool[i].nextseed = NULL;
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
			node_pool[i].context = NULL;
#endif
			return &node_pool[i];
		}
		SYS_ARCH_UNPROTECT(lev);
		if (prio < 0) {
			i++;
		} else if (--i < 0) {
			break;
		}
	}
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "No con_id available");
	return NULL;
}

node *create_node(int mode, s8_t role)
{
	return _create_node(mode, role, -1);
}

void delete_node(node * n)
{
	node *cn /* curr node */, *pn /* prev node */, 
	     *cur_seed;

	if (n == NULL) {
		return;
	}

	SYS_ARCH_DECL_PROTECT(lev);
	SYS_ARCH_PROTECT(lev);

	//need to remove it from mainlist first 
	for (cn = mainlist; cn != NULL; pn = cn, cn = cn->next) {
		node* recv_seed;
		if (cn == n) {
			pn->next = cn->next;
		}

		if (cn->role != NODE_ROLE_SERVER)
			continue;

		recv_seed = cn;
		cur_seed = cn->nextseed;
		while (cur_seed != NULL) {
			if (cur_seed == n) {
				recv_seed->nextseed = n->nextseed;
			}
			recv_seed = cur_seed;
			cur_seed = cur_seed->nextseed;
		}
	}
	SYS_ARCH_UNPROTECT(lev);

	if (n->role == NODE_ROLE_SERVER) {
		//node may have seed if it's under server mode
		while (n->nextseed != NULL) {
			cur_seed = n->nextseed;
			// only tcp/ssl seed has its own socket, udp seed uses its server's
			// so delete udp seed can't close socket which is used by server
			if (cur_seed->protocol == NODE_MODE_TCP && cur_seed->sockfd != INVALID_SOCKET_ID) {
				close(cur_seed->sockfd);
				cur_seed->sockfd = INVALID_SOCKET_ID;
			}
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
			else if (cur_seed->protocol == NODE_MODE_SSL && cur_seed->sockfd != INVALID_SOCKET_ID) {
				mbedtls_ssl_context *ssl = (mbedtls_ssl_context *) cur_seed->context;
				mbedtls_ssl_close_notify(ssl);
				mbedtls_net_context server_fd;
				server_fd.fd = cur_seed->sockfd;
				mbedtls_net_free(&server_fd);
				mbedtls_ssl_free(ssl);
				rtw_free(cur_seed->context);
				cur_seed->context = NULL;
			}
#endif
			// no task created for seed
			//if(s->handletask != NULL)
			//      vTaskDelete(s->handletask);
			n->nextseed = cur_seed->nextseed;
			cur_seed->con_id = INVALID_CON_ID;
		};
	}

	if (!((n->protocol == NODE_MODE_UDP) && (n->role == NODE_ROLE_SEED))) {
		if (n->sockfd != INVALID_SOCKET_ID) {
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
			if (n->protocol == NODE_MODE_SSL) {
				if (n->role == NODE_ROLE_SEED) {
					mbedtls_ssl_context *ssl = (mbedtls_ssl_context *) n->context;
					mbedtls_ssl_close_notify(ssl);
					mbedtls_net_context server_fd;
					server_fd.fd = cur_seed->sockfd;
					mbedtls_net_free(&server_fd);
					mbedtls_ssl_free(ssl);
				} else if (n->role == NODE_ROLE_CLIENT) {
					mbedtls_ssl_context *ssl = (mbedtls_ssl_context *) n->context;
					mbedtls_ssl_close_notify(ssl);
					mbedtls_net_context server_fd;
					server_fd.fd = n->sockfd;
					mbedtls_net_free(&server_fd);
					if (atcmd_ssl_cli_ca_crt[n->con_id]) {
						mbedtls_x509_crt_free(atcmd_ssl_cli_ca_crt[n->con_id]);
						rtw_free((void *) atcmd_ssl_cli_ca_crt[n->con_id]);
						atcmd_ssl_cli_ca_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_client_ca_crt[n->con_id]) {
						rtw_free(atcmd_ssl_client_ca_crt[n->con_id]);
						atcmd_ssl_client_ca_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_cli_crt[n->con_id]) {
						mbedtls_x509_crt_free(atcmd_ssl_cli_crt[n->con_id]);
						rtw_free((void *) atcmd_ssl_cli_crt[n->con_id]);
						atcmd_ssl_cli_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_client_crt[n->con_id]) {
						rtw_free(atcmd_ssl_client_crt[n->con_id]);
						atcmd_ssl_client_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_clikey_rsa[n->con_id]) {
						mbedtls_pk_free(atcmd_ssl_clikey_rsa[n->con_id]);
						rtw_free((void *) atcmd_ssl_clikey_rsa[n->con_id]);
						atcmd_ssl_clikey_rsa[n->con_id] = NULL;
					}
					if (atcmd_ssl_client_key[n->con_id]) {
						rtw_free(atcmd_ssl_client_key[n->con_id]);
						atcmd_ssl_client_key[n->con_id] = NULL;
					}
					mbedtls_ssl_free(ssl);
				} else {
					mbedtls_net_context server_fd;
					server_fd.fd = n->sockfd;
					mbedtls_net_free(&server_fd);
					if (atcmd_ssl_srv_crt[n->con_id]) {
						mbedtls_x509_crt_free(atcmd_ssl_srv_crt[n->con_id]);
						rtw_free((void *) atcmd_ssl_srv_crt[n->con_id]);
						atcmd_ssl_srv_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_server_crt[n->con_id]) {
						rtw_free(atcmd_ssl_server_crt[n->con_id]);
						atcmd_ssl_server_crt[n->con_id] = NULL;
					}
					if (atcmd_ssl_server_ca_list[n->con_id]) {
						rtw_free(atcmd_ssl_server_ca_list[n->con_id]);
						atcmd_ssl_server_ca_list[n->con_id] = NULL;
					}
					if (atcmd_ssl_srv_key[n->con_id]) {
						mbedtls_pk_free(atcmd_ssl_srv_key[n->con_id]);
						rtw_free((void *) atcmd_ssl_srv_key[n->con_id]);
						atcmd_ssl_srv_key[n->con_id] = NULL;
					}
					if (atcmd_ssl_server_key[n->con_id]) {
						rtw_free(atcmd_ssl_server_key[n->con_id]);
						atcmd_ssl_server_key[n->con_id] = NULL;
					}
				}
			} else
#endif
			{
				close(n->sockfd);
			}
			n->sockfd = INVALID_SOCKET_ID;
		}
	} else if (n->sockfd != INVALID_SOCKET_ID) {
		close(n->sockfd);
		n->sockfd = INVALID_SOCKET_ID;
	}
	//task will exit itself in fail case
	if (n->handletask) {
		vTaskDelete(n->handletask);
		n->handletask = NULL;
	}
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
	if (n->context) {
		rtw_free(n->context);
		n->context = NULL;
	}
#endif
	n->con_id = INVALID_CON_ID;
	return;
}

int hang_node(node * insert_node)
{
	node *n = mainlist;

	SYS_ARCH_DECL_PROTECT(lev);
	SYS_ARCH_PROTECT(lev);
	while (n->next != NULL) {
		n = n->next;
		// need to check for server in case that two conns are binded to same port,
		// because SO_REUSEADDR is enabled
		if (insert_node->role == NODE_ROLE_SERVER) {
			if ((n->port == insert_node->port)
			    && ((n->addr == insert_node->addr) && (n->role == insert_node->role)
				&& (n->protocol == insert_node->protocol))) {
				SYS_ARCH_UNPROTECT(lev);

				struct in_addr addr;
				addr.s_addr = htonl(insert_node->addr);
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
					   "This conn(IP:%s PORT:%d) already exist", inet_ntoa(addr), insert_node->port);
				return -1;
			}
		}
	}

	n->next = insert_node;
	SYS_ARCH_UNPROTECT(lev);
	return 0;
}

int hang_seednode(node * main_node, node * insert_node)
{
	node *n = main_node;

	SYS_ARCH_DECL_PROTECT(lev);
	SYS_ARCH_PROTECT(lev);
	while (n->nextseed != NULL) {
		n = n->nextseed;
		if ((n->port == insert_node->port) && (n->addr == insert_node->addr)) {
			SYS_ARCH_UNPROTECT(lev);
			struct in_addr addr;
			addr.s_addr = htonl(insert_node->addr);
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO,
				   "This seed IP:%s PORT:%d already exist", inet_ntoa(addr), insert_node->port);
			return -1;
		}
	}

	n->nextseed = insert_node;
	SYS_ARCH_UNPROTECT(lev);
	return 0;
}

node *seek_node(int con_id)
{
	node *n = mainlist;

	while (n->next != NULL) {
		n = n->next;
		if (n->con_id == con_id)
			return n;

		if (n->nextseed != NULL) {
			node *seed = n;
			do {
				seed = seed->nextseed;
				if (seed->con_id == con_id)
					return seed;
			} while (seed->nextseed != NULL);
		}
	}
	return NULL;
}

node *tryget_node(int n)
{
	SYS_ARCH_DECL_PROTECT(lev);
	if ((n < 0) || (n > NUM_NS)) {
		return NULL;
	}
	SYS_ARCH_PROTECT(lev);
	if (node_pool[n].con_id == INVALID_CON_ID || node_pool[n].sockfd == INVALID_SOCKET_ID) {
		SYS_ARCH_UNPROTECT(lev);
		return NULL;
	}
	SYS_ARCH_UNPROTECT(lev);
	return &node_pool[n];
}

int atcmd_lwip_receive_data(node * cn, u8 * buffer, u16 buffer_size, int *recv_size, u8_t * udp_clientaddr, u16_t * udp_clientport)
{
	struct timeval tv;
	fd_set readfds;
	int rt = 0, ret = 0, size = 0;

	FD_ZERO(&readfds);
	FD_SET(cn->sockfd, &readfds);
	tv.tv_sec = RECV_SELECT_TIMEOUT_SEC;
	tv.tv_usec = RECV_SELECT_TIMEOUT_USEC;
	ret = select(cn->sockfd + 1, &readfds, NULL, NULL, &tv);

	if (!((ret > 0) && (FD_ISSET(cn->sockfd, &readfds)))) {
		//AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, 
		//      "[ATPR] No receive event for con_id %d", cn->con_id);
		goto __ret;
	}

	if (cn->protocol == NODE_MODE_UDP) { //udp server receive from client
		if (cn->role == NODE_ROLE_SERVER) {
			struct sockaddr_in client_addr;
			u32_t addr_len = sizeof(struct sockaddr_in);

			rtw_memset((char *) &client_addr, 0, sizeof(client_addr));

			if ((size = recvfrom(cn->sockfd, buffer, buffer_size, 0, (struct sockaddr *) &client_addr, &addr_len)) <= 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR:Failed to receive data");
				rt = size;
			}
			//at_printf("[ATPR]:%d,%s,%d,%s\r\n with packet_size: %d\r\n",
			//      con_id, inet_ntoa(client_addr.sin_addr.s_addr), ntohs(client_addr.sin_port), rx_buffer, packet_size);
			//at_printf("\r\nsize: %d\r\n", recv_size);
			//at_printf("%s", rx_buffer);
			inet_ntoa_r(client_addr.sin_addr.s_addr, (char *) udp_clientaddr, 16);
			*udp_clientport = ntohs(client_addr.sin_port);
		} else {
			struct sockaddr_in serv_addr;
			u32_t addr_len = sizeof(struct sockaddr_in);

			rtw_memset((char *) &serv_addr, 0, sizeof(serv_addr));
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(cn->port);
			serv_addr.sin_addr.s_addr = htonl(cn->addr);

			if ((size = recvfrom(cn->sockfd, buffer, buffer_size, 0, (struct sockaddr *) &serv_addr, &addr_len)) <= 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR:Failed to receive data");
				rt = size;
			}
		}
	} else {
		#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
		//receive from seed or server
		if (cn->protocol == NODE_MODE_SSL) {
			size = mbedtls_ssl_read((mbedtls_ssl_context *) cn->context, buffer, buffer_size);
		} else
		#endif
		{
			size = read(cn->sockfd, buffer, buffer_size);
		}
		if (size == 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR:Connection is closed!");
			rt = -1;
		} else if (size < 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "[ATPR] ERROR:Failed to receive data.ret=-0x%x!", -size);
			rt = size;
		}
	}

__ret:
	if (rt >= 0) {
		*recv_size = size;
	} else {
#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
		if (cn->protocol == NODE_MODE_SSL) {
			mbedtls_ssl_close_notify((mbedtls_ssl_context *) cn->context);
			mbedtls_net_context server_fd;
			server_fd.fd = cn->sockfd;
			mbedtls_net_free(&server_fd);
			mbedtls_ssl_free((mbedtls_ssl_context *) cn->context);
		} else
#endif				//#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
		{
			close(cn->sockfd);
		}
		cn->sockfd = INVALID_SOCKET_ID;
	}
	return rt;
}

static void atcmd_lwip_receive_task(void *param)
{
	int i;
	(void) param;

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Enter auto receive mode");

	while (atcmd_lwip_is_autorecv_mode()) {
		for (i = 0; i < NUM_NS; ++i) {
			node *cn = NULL;

			if (!(cn = tryget_node(i))) {
				continue;
			}

			if ((cn->protocol == NODE_MODE_TCP || cn->protocol == NODE_MODE_SSL) && cn->role == NODE_ROLE_SERVER) {
				//TCP Server must receive data from the seed
				continue;
			}

			int recv_size = 0;
			u8_t udp_clientaddr[16] = { 0 };
			u16_t udp_clientport = 0;

			memset(rx_buffer, 0, rx_buffer_size);
			int rt = atcmd_lwip_receive_data(cn, rx_buffer, rx_buffer_size, &recv_size, udp_clientaddr, &udp_clientport);

			if (atcmd_lwip_is_tt_mode()) {
				if (rt >= 0 && recv_size) {
					rx_buffer[recv_size] = '\0';
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Recv[%d]:%s", recv_size, rx_buffer);
					at_print_data(rx_buffer, recv_size);
					rtw_msleep_os(20);
				}
				continue;
			}

			if (esp_compatible_recv) {
				if (rt < 0) {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+IPD Error %d receiving data, errno = %d(%s)", rt, errno, strerror(errno));
					if (cn->sockfd == INVALID_SOCKET_ID) {
						delete_node(cn);
					}
					continue;
				}
				if (recv_size == 0) {
					continue;
				}

				if (cn->protocol != NODE_MODE_UDP) {
					struct in_addr addr;

					addr.s_addr = htonl(cn->addr);
					sprintf((char*)udp_clientaddr, "%s", inet_ntoa(addr));
					udp_clientport = cn->port;
				}

				rx_buffer[recv_size] = '\0';

				LOG_SERVICE_LOCK();
				// Receiving data header
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+IPD %d", recv_size);
				at_printf("\r\n+IPD,%d,%d,%s,%d:",
					cn->con_id,
					recv_size,
					udp_clientaddr,
					udp_clientport);
				// Receiving data body
				at_print_data(rx_buffer, recv_size);
				LOG_SERVICE_UNLOCK();

				continue;
			}

			if (rt >= 0) {
				if (recv_size) {
					rx_buffer[recv_size] = '\0';
					LOG_SERVICE_LOCK();
					if (cn->protocol == NODE_MODE_UDP && cn->role == NODE_ROLE_SERVER) {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO,
							   "\r\n[ATPR] OK,%d,%d,%s,%d:%s", recv_size, cn->con_id,
							   udp_clientaddr, udp_clientport, rx_buffer);
						at_printf("\r\n[ATPR] OK,%d,%d,%s,%d:", recv_size, cn->con_id,
							  udp_clientaddr, udp_clientport);
					} else {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO,
							   "\r\n[ATPR] OK,%d,%d:%s", recv_size, cn->con_id, rx_buffer);
						at_printf("\r\n[ATPR] OK,%d,%d:", recv_size, cn->con_id);
					}
					at_print_data(rx_buffer, recv_size);
					at_printf(STR_END_OF_ATCMD_RET);
					LOG_SERVICE_UNLOCK();
				}
			} else {
				LOG_SERVICE_LOCK();
				at_printf("\r\n[ATPR] ERROR:%d,%d", rt, cn->con_id);
				at_printf(STR_END_OF_ATCMD_RET);
				LOG_SERVICE_UNLOCK();
			}
		}
	}

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Leave auto receive mode");

	vTaskDelete(NULL);
}

int atcmd_lwip_start_autorecv_task(void)
{
	atcmd_lwip_set_autorecv_mode(TRUE);
	if (xTaskCreate
	    (atcmd_lwip_receive_task, ((const char *) "atcmd_lwip_receive_task"), ATCP_STACK_SIZE, NULL,
	     ATCMD_LWIP_TASK_PRIORITY, NULL) != pdPASS) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: Create receive task failed.");
		atcmd_lwip_set_autorecv_mode(FALSE);
		return -1;
	}
	return 0;
}

static void _tt_wait_rx_complete(void)
{
	s32 tick_current = rtw_get_current_time();

	while (rtw_systime_to_ms(tick_current - atcmd_lwip_tt_lasttickcnt) < ATCMD_LWIP_TT_MAX_DELAY_TIME_MS) {
		rtw_msleep_os(5);
		tick_current = rtw_get_current_time();
	}
}

static void atcmd_lwip_tt_handler(void *param)
{
	struct sockaddr_in cli_addr;
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Enter TT data mode");
	(void) param;

	while (rtw_down_sema(&atcmd_lwip_tt_sema) == _SUCCESS) {
		_lock lock;
		_irqL irqL;
		int tt_size = 0;
		_tt_wait_rx_complete();

		rtw_enter_critical(&lock, &irqL);
		if ((atcmd_lwip_tt_datasize >= 4) && (rtw_memcmp(log_buf, "----", 4) == _TRUE)) {
			atcmd_lwip_set_tt_mode(FALSE);
			atcmd_lwip_tt_datasize = 0;
			rtw_exit_critical(&lock, &irqL);
			break;
		}
		rtw_memcpy(tx_buffer, log_buf, atcmd_lwip_tt_datasize);
		tt_size = atcmd_lwip_tt_datasize;
		atcmd_lwip_tt_datasize = 0;
		rtw_exit_critical(&lock, &irqL);
		tx_buffer[tt_size] = '\0';
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Send[%d]:%s", tt_size, tx_buffer);
		atcmd_lwip_send_data(mainlist->next, tx_buffer, tt_size, cli_addr);
	}

	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Leave TT data mode");
	rtw_free_sema(&atcmd_lwip_tt_sema);
	atcmd_lwip_set_autorecv_mode(FALSE);
	at_printf(STR_END_OF_ATCMD_RET);	//mark return to command mode
	vTaskDelete(NULL);
}

int atcmd_lwip_start_tt_task(void)
{
	int ret;
	int enable = 1;
	int send_timeout = 20;	//20 milliseconds
	node *n = mainlist->next;
	ret = setsockopt(n->sockfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
	if (ret < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "set TCP_NODELAY error! ");
		goto err_exit;
	}
#if LWIP_TCP_KEEPALIVE
	ret = setsockopt(n->sockfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
	if (ret < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "set SO_KEEPALIVE error! ");
	}
#endif
#if LWIP_SO_SNDTIMEO
	ret = setsockopt(n->sockfd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(int));
	if (ret < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "SO_SNDTIMEO error! ");
	}
#endif

	rtw_init_sema(&atcmd_lwip_tt_sema, 0);
	atcmd_lwip_set_tt_mode(TRUE);
	if (xTaskCreate
	    (atcmd_lwip_tt_handler, ((const char *) "tt_hdl"), ATCP_STACK_SIZE, NULL, ATCMD_LWIP_TASK_PRIORITY,
	     &atcmd_lwip_tt_task) != pdPASS) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ERROR: Create tt task failed.");
		goto err_exit;
	}
	rtw_msleep_os(20);
	if (! atcmd_lwip_is_autorecv_mode()) {
		if (atcmd_lwip_start_autorecv_task()) {
			vTaskDelete(atcmd_lwip_tt_task);
			goto err_exit;
		}
	}

	return 0;

      err_exit:
	atcmd_lwip_set_tt_mode(FALSE);
	return -1;
}

void atcmd_lwip_erase_info(void)
{
	atcmd_update_partition_info(AT_PARTITION_LWIP, AT_PARTITION_ERASE, NULL, 0);
}

int atcmd_lwip_write_info_to_flash(struct atcmd_lwip_conn_info *cur_conn, int enable)
{
	struct atcmd_lwip_conf read_data = { 0 };
	int i = 0, found = 0;

	atcmd_update_partition_info(AT_PARTITION_LWIP, AT_PARTITION_READ, (u8 *) & read_data, sizeof(struct atcmd_lwip_conf));

	//fake that the conn exists already when disabling or there is no active conn on this moment
	if (enable == 0) {
		atcmd_lwip_erase_info();
		goto exit;
	}

	if (read_data.conn_num < 0 || read_data.conn_num > ATCMD_LWIP_CONN_STORE_MAX_NUM) {
		read_data.conn_num = 0;
		read_data.last_index = -1;
	}

	for (i = 0; i < read_data.conn_num; i++) {
		if (rtw_memcmp((u8 *) cur_conn, (u8 *) & read_data.conn[i], sizeof(struct atcmd_lwip_conn_info)) == _TRUE) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "the same profile found in flash");
			found = 1;
			break;
		}
	}

	if (!found) {
		read_data.last_index++;
		if (read_data.last_index >= ATCMD_LWIP_CONN_STORE_MAX_NUM)
			read_data.last_index -= ATCMD_LWIP_CONN_STORE_MAX_NUM;
		rtw_memcpy((u8 *) & read_data.conn[read_data.last_index], (u8 *) cur_conn, sizeof(struct atcmd_lwip_conn_info));
		read_data.conn_num++;
		if (read_data.conn_num > ATCMD_LWIP_CONN_STORE_MAX_NUM)
			read_data.conn_num = ATCMD_LWIP_CONN_STORE_MAX_NUM;
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "not the same proto/addr/port, write new profile to flash");
	}
	if (!found || read_data.enable != enable) {
		read_data.enable = enable;
		atcmd_update_partition_info(AT_PARTITION_LWIP, AT_PARTITION_WRITE, (u8 *) & read_data, sizeof(struct atcmd_lwip_conf));
	}
      exit:
	return 0;
}

int atcmd_lwip_read_info_from_flash(u8 * read_data, u32 read_len)
{
	atcmd_update_partition_info(AT_PARTITION_LWIP, AT_PARTITION_READ, read_data, read_len);
	return 0;
}

int atcmd_lwip_auto_connect(void)
{
	struct atcmd_lwip_conf read_data = { 0 };
	struct atcmd_lwip_conn_info *re_conn;
	node *re_node = NULL;
	int i, rt = 0;
	int last_index;

	atcmd_lwip_read_info_from_flash((u8 *) & read_data, sizeof(struct atcmd_lwip_conf));
	if (read_data.enable == 0) {
		rt = 1;
		goto exit;
	}
	if (read_data.conn_num > ATCMD_LWIP_CONN_STORE_MAX_NUM || read_data.conn_num <= 0) {
		rt = 2;
		goto exit;
	}

	last_index = read_data.last_index;
	for (i = 0; i < read_data.conn_num; i++) {
		rt = 0;
		re_conn = &read_data.conn[last_index];
		last_index++;
		if (last_index >= ATCMD_LWIP_CONN_STORE_MAX_NUM)
			last_index -= ATCMD_LWIP_CONN_STORE_MAX_NUM;
		re_node = create_node(re_conn->protocol, re_conn->role);
		if (re_node == NULL) {
			rt = 3;
			break;
		}
		re_node->addr = re_conn->remote_addr;
		re_node->port = re_conn->remote_port;
		re_node->local_addr = re_conn->local_addr;
		re_node->local_port = re_conn->local_port;
		if (re_node->role == NODE_ROLE_SERVER) {
			//TODO: start server here
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Auto connect isn't enabled for server");
			rt = 4;
			goto exit;
		}
		struct in_addr addr;
		addr.s_addr = htonl(re_node->addr);
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "\r\nAuto connect to: %d,%s,%d", re_node->protocol, inet_ntoa(addr), re_node->port);

#if (ATCMD_VER == ATVER_2) && ATCMD_SUPPORT_SSL
		if (re_node->protocol == NODE_MODE_SSL) {
			int ret;
			mbedtls_net_context server_fd;
			char c_remote_addr[16];
			if (inet_ntoa_r(addr, c_remote_addr, sizeof(c_remote_addr)) == NULL) {
				delete_node(re_node);
				re_node = NULL;
				rt = 5;
				continue;
			}
			server_fd.fd = re_node->sockfd;
			char *node_port_str = atcmd_lwip_itoa(re_node->port);
			if ((ret = mbedtls_net_connect(&server_fd, c_remote_addr, node_port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Failed to net_connect!ret=%d", ret);
				delete_node(re_node);
				re_node = NULL;
				rt = 6;
				continue;
			}
			re_node->sockfd = server_fd.fd;
			free(node_port_str);
			/***********************************************************
			*  SSL 1. Setup stuff for this ssl connection
			************************************************************/
			int retry_count = 0;
			mbedtls_ssl_context *ssl;
			mbedtls_ssl_config *conf;

			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Setting up the SSL/TLS structure...");
			mbedtls_platform_set_calloc_free(my_calloc, vPortFree);
			ssl = (mbedtls_ssl_context *) rtw_zmalloc(sizeof(mbedtls_ssl_context));
			conf = (mbedtls_ssl_config *) rtw_zmalloc(sizeof(mbedtls_ssl_config));

			if ((ssl == NULL) || (conf == NULL)) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "malloc fail for ssl");
				rt = 7;
				delete_node(re_node);
				re_node = NULL;
				continue;
			}

			mbedtls_ssl_init(ssl);
			mbedtls_ssl_config_init(conf);

			if ((ret = mbedtls_ssl_config_defaults(conf,
							       MBEDTLS_SSL_IS_CLIENT,
							       MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ssl config defaults fail");
				rt = 8;
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				delete_node(re_node);
				re_node = NULL;
				continue;
			}
			mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
			mbedtls_ssl_conf_rng(conf, atcmd_ssl_random, NULL);
			mbedtls_ssl_set_bio(ssl, &re_node->sockfd, mbedtls_net_send, mbedtls_net_recv, NULL);
			mbedtls_ssl_conf_dbg(conf, atcmd_ssl_debug, NULL);

			if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ssl setup fail");
				rt = 9;
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				delete_node(re_node);
				re_node = NULL;
				continue;
			}
#ifdef MBEDTLS_DEBUG_C
			mbedtls_debug_set_threshold(ATCMD_SSL_DEBUG_LEVEL);
#endif
			/***********************************************************
			*  SSL 2. Wait for the ssl handshake done
			************************************************************/
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Performing the SSL/TLS handshake...");
			while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
				if (retry_count >= 5) {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "ssl_handshake failed -0x%x\n", -ret);
					rt = 10;
					break;
				}
				retry_count++;
			}
			if (ret != 0) {
				rtw_free((void *) ssl);
				rtw_free((void *) conf);
				delete_node(re_node);
				re_node = NULL;
				rt = 11;
				continue;
			}
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Connect to Server successful!");
			/***********************************************************
			*  SSL 3. Hang node on mainlist for global management
			************************************************************/
			re_node->context = (void *) ssl;
			if (hang_node(re_node) < 0) {
				rt = 12;
			}
			break;
		} else
#endif
		{
			if (re_node->protocol == NODE_MODE_UDP)
				re_node->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
			else if (re_node->protocol == NODE_MODE_TCP)
				re_node->sockfd = socket(AF_INET, SOCK_STREAM, 0);
			else
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Unknown connection type[%d]", re_node->protocol);

			if (re_node->sockfd == INVALID_SOCKET_ID) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Failed to create sock_fd!");
				rt = 13;
				break;
			}

			if (re_node->protocol == NODE_MODE_TCP) {	//TCP MODE
				struct sockaddr_in c_serv_addr;
				rtw_memset(&c_serv_addr, 0, sizeof(c_serv_addr));
				c_serv_addr.sin_family = AF_INET;
				c_serv_addr.sin_addr.s_addr = htonl(re_node->addr);
				c_serv_addr.sin_port = htons(re_node->port);
				if (connect(re_node->sockfd, (struct sockaddr *) &c_serv_addr, sizeof(c_serv_addr)) == 0) {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Connect to Server successful!");
					if (hang_node(re_node) < 0) {
						rt = 14;
					}
					break;
				} else {
					AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Connect to Server failed(%d)!", errno);
					rt = 15;
					delete_node(re_node);
					re_node = NULL;
					continue;	//try next conn
				}
			} else {
#if IP_SOF_BROADCAST && IP_SOF_BROADCAST_RECV
				/* all ones (broadcast) or all zeroes (old skool broadcast) */
				if ((re_node->addr == INADDR_BROADCAST) || (re_node->addr == INADDR_ANY)) {
					int so_broadcast = 1;
					if (setsockopt(re_node->sockfd, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast)) < 0) {
						rt = 16;
						delete_node(re_node);
						re_node = NULL;
						continue;
					}
				}
#endif
#if LWIP_IGMP
				ip_addr_t dst_addr;
				dst_addr.addr = htonl(re_node->addr);
				if (ip_addr_ismulticast(&dst_addr)) {
					struct ip_mreq imr;
					struct in_addr intfAddr;
					// Set NETIF_FLAG_IGMP flag for netif which should process IGMP messages
					xnetif[0].flags |= NETIF_FLAG_IGMP;
					imr.imr_multiaddr.s_addr = htonl(re_node->addr);
					imr.imr_interface.s_addr = htonl(INADDR_ANY);
					if (setsockopt(re_node->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr)) < 0) {
						xnetif[0].flags &= ~NETIF_FLAG_IGMP;
						rt = 17;
						delete_node(re_node);
						re_node = NULL;
						continue;
					}
					intfAddr.s_addr = INADDR_ANY;
					if (setsockopt(re_node->sockfd, IPPROTO_IP, IP_MULTICAST_IF, &intfAddr, sizeof(struct in_addr)) < 0) {
						xnetif[0].flags &= ~NETIF_FLAG_IGMP;
						rt = 18;
						delete_node(re_node);
						re_node = NULL;
						continue;
					}
				}
#endif
				if (re_node->local_port) {
					struct sockaddr_in addr;
					rtw_memset(&addr, 0, sizeof(addr));
					addr.sin_family = AF_INET;
					addr.sin_port = htons(re_node->local_port);
					addr.sin_addr.s_addr = htonl(INADDR_ANY);
					if (bind(re_node->sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
						AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "bind sock error!");
						rt = 19;
						delete_node(re_node);
						re_node = NULL;
						continue;
					}
				}
				if (hang_node(re_node) < 0) {
					rt = 20;
				}
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "UDP client starts successful!");
				break;
			}
		}
	}

      exit:
	if (re_node && rt)
		delete_node(re_node);
	return rt;
}

int atcmd_lwip_restore_from_flash(void)
{
	int ret = -1;
	if (atcmd_lwip_auto_connect() == 0) {
		if (atcmd_lwip_start_tt_task() == 0)
			ret = 0;
	}

	if (esp_compatible_recv) {
		atcmd_lwip_start_autorecv_task();
	}

	return ret;
}

/* DNS function, resolve domain name to ip address */
void fATCIPDOMAIN(void *arg)
{
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	char *hostname;
	struct in_addr addr;
	struct hostent *host;

	if (!arg) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	argc = parse_param(arg, argv);
	if (argc < 2 || argv[1] == NULL) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	hostname = argv[1];

	if (inet_aton(hostname, &addr) == 0) {
		host = gethostbyname(hostname);
		if (!host) {
			at_printf(STR_RESP_FAIL);
			return;
		}
		rtw_memcpy(&addr, host->h_addr, sizeof host->h_addr);
	}
	// Query
	at_printf("+CIPDOMAIN:\"%s\"\r\n", ip_ntoa((ip_addr_t *) & addr));
	at_printf(STR_RESP_OK);
	return;
}

/*
 * type could be
 *   NODE_MODE_SSL,
 *   NODE_MODE_TCP,
 *   NODE_MODE_UDP
 */
const char* type2string(int type)
{
	const char* ts = "UDP";

	switch (type) {
	case NODE_MODE_SSL:
		ts = "SSL"; break;
	case NODE_MODE_TCP:
		ts = "TCP"; break;
	default:
	case NODE_MODE_UDP:
		ts = "UDP"; break;
	}
	return ts;
}


void esp_list_links(void *arg) {
	node *n = mainlist->next;
	struct in_addr addr;

	(void) arg;

	while (n != NULL) {
		if (n->con_id == INVALID_CON_ID)
			continue;

		addr.s_addr = htonl(n->addr);
		/* +CIPSTATUS:<link-id>,<type>,<remote-ip>,<remote-port>,<local-port>,<tetype> */
		at_printf("+CIPSTATUS:%d,\"%s\",\"%s\",%d,%d,%d\r\n",
			n->con_id,
			type2string(n->protocol),
			inet_ntoa(addr),
			n->port,
			n->local_port,
			(n->role == NODE_ROLE_SERVER)
			);

		n = n->next;
	}
	return;
}

/*
 * type could be "TCP", "UDP", "SSL"
 */
int string2type(char *type)
{
	if (strcasecmp(type, "SSL") == 0) {
		return NODE_MODE_SSL;
	}
	if (strcasecmp(type, "TCP") == 0) {
		return NODE_MODE_TCP;
	}
	if (strcasecmp(type, "UDP") == 0) {
		return NODE_MODE_UDP;
	}
	return -1;
}

/*
 * Note fATXXX functions called by thread "log_service" are already locked with LOG_SERVICE_LOCK.
 * If this function is call directly by fATXXX() function (not in a uniq thread),
 * remove LOG_SERVICE_LOCK && vTaskDelete()
 */
static void client_esp_task(void *param)
{
	char c_remote_addr[16];
	int c_sockfd;
	struct sockaddr_in c_serv_addr;
	node* client = (node*)param;
	int r = 0;

	if (!client) {
		r = -20;
		goto _e_ret;
	}

	struct in_addr c_addr;
	c_addr.s_addr = htonl(client->addr);
	if (inet_ntoa_r(c_addr, c_remote_addr, sizeof(c_remote_addr)) == NULL) {
		r = -1;
		goto _e_ret;
	}

	/***********************************************************
	* Create socket and set socket options, then bind socket to local port
	************************************************************/
	int c_mode = client->protocol;

	if (c_mode == NODE_MODE_UDP)
		c_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	else if (c_mode == NODE_MODE_TCP)
		c_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	else
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Unknown connection type[%d]", c_mode);

	if (c_sockfd == INVALID_SOCKET_ID) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "Failed to create sock_fd! %d(%s)", errno, strerror(errno));
		r = -2;
		goto _e_ret;
	}
	rtw_memset(&c_serv_addr, 0, sizeof(c_serv_addr));
	c_serv_addr.sin_family = AF_INET;
	c_serv_addr.sin_addr.s_addr = inet_addr(c_remote_addr);
	c_serv_addr.sin_port = htons(client->port);	// remote port */
	static int create_count = -1;
	++create_count;
	AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "%d OK to create sock_fd %d!", create_count, c_sockfd);

	/***********************************************************
	* Assign socket fd to the node used for this client
	************************************************************/
	client->sockfd = c_sockfd;

	if (c_mode == NODE_MODE_TCP) {	//TCP MODE
		/***********************************************************
		*  TCP 1. Connect a netconn to a specific remote IP address and port
		************************************************************/
		if (connect(c_sockfd, (struct sockaddr *) &c_serv_addr, sizeof(c_serv_addr)) == 0) {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "Connect to Server successful!");
			/***********************************************************
			*  TCP 2. Hand node on mainlist for global management if connect success
			************************************************************/
			if (hang_node(client) < 0) {
				r = -3;
				goto _e_ret;
			}
		} else {
			/***********************************************************
			*  TCP 2. Free node if connect fail
			************************************************************/
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR,
				   "[ATPC] ERROR:Connect to Server failed!");
			r = -4;
			goto _e_ret;
		}
	} else {
		#if IP_SOF_BROADCAST && IP_SOF_BROADCAST_RECV
		/* all ones (broadcast) or all zeroes (old skool broadcast) */
		if ((c_serv_addr.sin_addr.s_addr == htonl(INADDR_BROADCAST)) ||
		    (c_serv_addr.sin_addr.s_addr == htonl(INADDR_ANY))) {
			int so_broadcast = 1;
			if (setsockopt(c_sockfd, SOL_SOCKET, SO_BROADCAST, &so_broadcast,
				       sizeof(so_broadcast)) < 0) {
				r = -5;
				goto _e_ret;
			}
		}
		#endif

		#if LWIP_IGMP
		ip_addr_t dst_addr;
		dst_addr.addr = c_serv_addr.sin_addr.s_addr;
		if (ip_addr_ismulticast(&dst_addr)) {
			struct ip_mreq imr;
			struct in_addr intfAddr;
			// Set NETIF_FLAG_IGMP flag for netif which should process IGMP messages
			xnetif[0].flags |= NETIF_FLAG_IGMP;
			imr.imr_multiaddr.s_addr = c_serv_addr.sin_addr.s_addr;
			imr.imr_interface.s_addr = INADDR_ANY;
			if (setsockopt(c_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr)) < 0) {
				xnetif[0].flags &= ~NETIF_FLAG_IGMP;
				r = -6;
				goto _e_ret;
			}
			intfAddr.s_addr = INADDR_ANY;
			if (setsockopt(c_sockfd, IPPROTO_IP, IP_MULTICAST_IF, &intfAddr, sizeof(struct in_addr)) < 0) {
				xnetif[0].flags &= ~NETIF_FLAG_IGMP;
				r = -7;
				goto _e_ret;
			}
		}
		#endif

		if (client->local_port) {
			struct sockaddr_in addr;

			rtw_memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(client->local_port);
			addr.sin_addr.s_addr = htonl(INADDR_ANY);

			if (bind(client->sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "bind sock error!");
				r = -8;
				goto _e_ret;
			}
		}
		if (hang_node(client) < 0) {
			r = -9;
			goto _e_ret;
		}

		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_INFO, "UDP client starts successful!");
	}
	goto __ret;

_e_ret:
	if (client) {
		delete_node(client);
	}
__ret:
	// LOG_SERVICE_LOCK();
	if (r >= 0) {
		struct in_addr addr;
		addr.s_addr = htonl(client->addr);

		at_set_ipstatus(ESP_IPSTAT_CONN_CREATED);

		at_printf("+LINK_CONN:%d,%d,\"%s\",%d,\"%s\",%d,%d\r\n",
			0, // Result code, 0 -- Success
			client->con_id,
			type2string(client->protocol),
			(client->role == NODE_ROLE_SERVER),
			inet_ntoa(addr),
			client->port,
			client->local_port
			);
		at_printf(STR_RESP_OK);
	} else {
		at_printf("\r\n+CIPSTART: Error %d\r\n", -100 + r);
		at_printf(STR_RESP_FAIL);
	}
	// LOG_SERVICE_UNLOCK();
	// vTaskDelete(NULL);
	return;
}

/* Create TCP/UDP client socket */
void fATCIPSTART(void *arg)
{
	int r = 0;
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int linkid, mode;
	struct in_addr addr;
	const int local_port = 0;
	node *clientnode = NULL;
	int remote_port;

	/* TODO: transparent transmission mode checking */

	if (!arg || (argc = parse_param(arg, argv)) < 5) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	linkid = atoi(argv[1]);
	mode = string2type(argv[2]);
	if (mode < 0) {
		r = -1;
		goto __ret;
	}

	if (inet_aton(argv[3], &addr) == 0) {
		struct hostent *host;

		host = gethostbyname(argv[3]);
		if (host) {
			rtw_memcpy(&addr, host->h_addr, sizeof host->h_addr);
		} else {
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSTART: Host '%s' not found", argv[3]);
			r = -2;
			goto __ret;
		}
	}

	remote_port = atoi((char *) argv[4]);
	if (remote_port < 0 || remote_port > 65535) {
		r = -3;
		goto __ret;
	}

	clientnode = _create_node(mode, NODE_ROLE_CLIENT, linkid);
	if (clientnode == NULL) {
		r = -4;
		goto __ret;
	}
	clientnode->port = remote_port;
	clientnode->addr = ntohl(addr.s_addr);
	clientnode->local_port = local_port;

	#if 0
	if (xTaskCreate(client_esp_task, "clt_tsk", ATCP_STACK_SIZE, clientnode, ATCMD_LWIP_TASK_PRIORITY, NULL) != pdPASS) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSTART: Create TCP/UDP/SSL client task failed");
		r = -5;
		goto __clean_node;
	}
	#else
	/* make it synchronous */
	client_esp_task(clientnode);
	#endif
	goto __ret;

__clean_node:
	if (clientnode) {
		delete_node(clientnode);
	}

__ret:
	if (r < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSTART: Error %d", r);
		at_printf(STR_RESP_FAIL);
	} else {
		// at_printf(STR_RESP_OK);
	}
	return;
}


static int _at_data_counter = 0;
int at_get_data_counter(void) {
	return _at_data_counter;
}

int at_set_data_counter(int size) {
	_at_data_counter = size;
	return size;
}

#define ATPB_W (&at_net_pbufs[0])
#define ATPB_R (&at_net_pbufs[1])
static atcmd_pbuf_t at_net_pbufs[2];

int at_net_store_data(const uint8_t* buf, uint32_t size) {
	int old_mask = 0;
	struct pbuf* pb;

	if (size >= UINT16_MAX) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "L%d requested store size too big =%d", __LINE__, (int)size);
		return -1;
	}

	if (!(pb = pbuf_alloc(PBUF_RAW, size, PBUF_RAM))) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "L%d at overflow size=%d", __LINE__, (int)size);
		return -2;
	}

	pbuf_take(pb, buf, size);

	// should protect the pbuf list
	if (__get_IPSR()) {
		old_mask = taskENTER_CRITICAL_FROM_ISR();
	} else {
		taskENTER_CRITICAL();
	}

	if (ATPB_W->pb == NULL) {
		ATPB_W->pb = pb;
	} else {
		pbuf_cat(ATPB_W->pb, pb);
	}

	_at_data_counter -= size;
	if (_at_data_counter < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "L%d at error size=%d", __LINE__, (int)size);
		_at_data_counter = 0;
	}

	if (__get_IPSR()) {
		taskEXIT_CRITICAL_FROM_ISR(old_mask);
	} else {
		taskEXIT_CRITICAL();
	}
	return 0;
}

int at_net_load_data(uint8_t* buf, uint32_t size) {
	uint16_t len;

	if (size > UINT16_MAX) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "L%d at load data overflow size=%d", __LINE__, (int)size);
		return -1;
	}

	// Move the pbuf list from Writing Slot
	// to Reading Slot.
	if (ATPB_R->pb == NULL && ATPB_W->pb != NULL) {
		taskENTER_CRITICAL();

		ATPB_R->pb = ATPB_W->pb;
		ATPB_W->pb = NULL;
		taskEXIT_CRITICAL();

		ATPB_R->iter = 0;
	}

	len = size;
	// Preparing data & length to send.
	if (ATPB_R->pb == NULL) {
		len = 0;
	} else if (len > ATPB_R->pb->tot_len - ATPB_R->iter){
		len = ATPB_R->pb->tot_len - ATPB_R->iter;
	}

	if (len) {
		pbuf_copy_partial(ATPB_R->pb, buf, len, ATPB_R->iter);

		ATPB_R->iter += len;
		if (ATPB_R->iter >= ATPB_R->pb->tot_len) {
			/* Free the pbuf not required anymore */
			pbuf_free(ATPB_R->pb);
			ATPB_R->pb = NULL;
		}
	}
	return len;
}

static void client_send_task(void *param)
{
	node* nd = (node*) param;
	if (!nd) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSEND: Error task client_send_task argument NULL");
		goto __ret;
	}

	// After data mux been setup.
	at_set_data_counter(nd->tx_len);

	// Inform the coperative device we prepared well for receving DATA
	LOG_SERVICE_LOCK();
	at_printf(STR_RESP_OK ">");

	int err_del_node = 0;
	int timeout = 0;
	while (nd->tx_len > 0) {
		int n = at_net_load_data(_tx_buffer, sizeof _tx_buffer);

		if (n <= 0) {
			rtw_msleep_os(1);
			if (++timeout > 5000/* seconds */) {
				break;
			}
			continue;
		}

		int r = atcmd_lwip_send_data(nd, _tx_buffer, n, nd->udp_dest);
		if (r) {
			if (errno == ENOTCONN || errno == EBADF) {
				err_del_node = 1;
			}
			AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSEND: Error %d sending data, errno = %d(%s)", r, errno, strerror(errno));
			break;
		}
		nd->tx_len -= n;
	}
	LOG_SERVICE_UNLOCK();

__ret:
	if (nd->tx_len) {
		// drain all data pbufs left
		while (nd->tx_len > 0) {
			int n = at_net_load_data(_tx_buffer, sizeof _tx_buffer);

			if (n <= 0) {
				rtw_msleep_os(1);
				if (++timeout > 5000/* seconds */) {
					break;
				}
				continue;
			}

			nd->tx_len -= n;
		}
		at_printf("\r\nSEND FAIL\r\n");
	} else {
		at_printf("\r\nSEND OK\r\n");
	}
	at_set_data_counter(nd->tx_len = 0);

	if (err_del_node) {
		at_printf("\r\n%d,CLOSED\r\n", nd->con_id);
		delete_node(nd);
	}

	vTaskDelete(NULL);
	return;
}

void fATCIPSEND(void *arg)
{
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int linkid = INVALID_CON_ID;
	node *cn = NULL;
	struct sockaddr_in cli_addr;
	int r = 0;

	argc = parse_param(arg, argv);

	if (argc < 3) {
		r = -1;
		goto __ret;
	}

	linkid = atoi((char *) argv[1]);
	if ((cn = seek_node(linkid)) == NULL) {
		r = -2;
		goto __ret;
	}

	cn->tx_len = atoi((char *) argv[2]);
	// TODO: check length

	if (argc >= 5) {
		char clientipstr[16] = { 0 };

		strcpy(clientipstr, (char *) argv[3]);
		cli_addr.sin_family = AF_INET;
		cli_addr.sin_port = htons(atoi((char *) argv[4]));

		if (inet_aton(clientipstr, &cli_addr.sin_addr) == 0) {
			r = -4;
			goto __ret;
		}
		cn->udp_dest = cli_addr;
	}

	if (xTaskCreate(client_send_task, "clt_tx", ATCP_STACK_SIZE,
	                cn, ATCMD_LWIP_TASK_PRIORITY, NULL) != pdPASS
	) {
		r = -5;
		goto __ret;
	}

__ret:
	if (r < 0) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPSEND: Error %d", r);
		at_printf(STR_RESP_FAIL);
	}
	return;
}

void fATCIPCLOSE(void *arg)
{
	int linkid = INVALID_CON_ID;
	node* cn = NULL;
	int rt = 0;

	if (!arg) {
		rt = -1;
		goto __ret;
	}

	linkid = atoi((char *) arg);

	if (linkid < INVALID_CON_ID || linkid >= NUM_NS) {
		rt = -2;
		goto __ret;
	}

	if ((cn = seek_node(linkid)) == NULL) {
		rt = -3;
		goto __ret;
	}
	delete_node(cn);


__ret:
	cn = NULL;
	if (rt) {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "+CIPCLOSE: Error %d", rt);
		at_printf(STR_RESP_FAIL);
	} else {
		at_printf("\r\n%d,CLOSED\r\n", linkid);
		at_printf(STR_RESP_OK);
	}
	return;
}

void fATCIPDNS(void *arg) {
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	ip_addr_t ipaddr[2];

	if (!arg) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	argc = parse_param(arg, argv);
	if (argc < 2 || argv[1] == NULL) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	// Query
	if (*argv[1] == '?') {
		ipaddr[0] = *dns_getserver(0);
		ipaddr[1] = *dns_getserver(1);

		// TODO, document error
		at_printf("+CIPDNS:0,\"%s\"", ip_ntoa(&ipaddr[0]));
		//if (!ip_addr_cmp(&ipaddr[1], IP_ADDR_ANY)) {
		at_printf(",\"%s\"\r\n", ip_ntoa(&ipaddr[1]));
		at_printf(STR_RESP_OK);
		return;
	}

	// Set
	int en = atoi((char *) argv[1]);
	if (!en || argc <= 2) {
		IP_ADDR4(&ipaddr[0], 208, 67, 222, 222);
		dns_setserver(0, &ipaddr[0]);
		goto __ret;
	}

	// DNS1
	inet_aton(argv[2], &ipaddr[0]);
	dns_setserver(0, &ipaddr[0]);

	// DNS2
	if (argc >= 4) {
		inet_aton(argv[3], &ipaddr[1]);
		dns_setserver(1, &ipaddr[1]);
	}

__ret:
	at_printf(STR_RESP_OK);
	return;

}

void fATCIPSERVERMAXCONN(void *arg) {
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int rt = 0;

	if (!arg || (argc = parse_param(arg, argv)) < 2) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	// Query
	if (*argv[1] == '?') {
		at_printf("+CIPSERVERMAXCONN:%d\r\n", server_max_conn);
		at_printf(STR_RESP_OK);
		return;
	}

	rt = atoi((char *) argv[1]);
	if (0 >= rt || rt > NUM_NS - 2) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	server_max_conn = rt;
	at_printf(STR_RESP_OK);
	return;
}

void fATCIPSERVER(void *arg) {
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int rt = 0;

	if (!arg || (argc = parse_param(arg, argv)) < 2) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	// Query
	if (*argv[1] == '?') {
		// TODO: SSL support
		at_printf("+CIPSERVER:%d,%d,\"%s\",%d\r\n",
			(servernode && servernode->con_id != INVALID_CON_ID && servernode->handletask),
			servernode? servernode->local_port: 0,
			type2string(servernode->protocol),
			0);
		at_printf(STR_RESP_OK);
		return;
	}

	int en = atoi((char *) argv[1]);
	if (!en) {
		// remove server node only
		// task will be destroyed automatically.
		goto _e_ret;
	}

	if (servernode) {
		rt = -2;
		goto _e_ret;
	}

	int local_port = 333;
	if (argc >= 3) {
		local_port = atoi((char *) argv[2]);
	}
	if (local_port < 0 || local_port > 65535) {
		rt = -4;
		goto _e_ret;
	}

	int mode = argc >= 4? string2type((char *)argv[3]): NODE_MODE_TCP;

	servernode = _create_node(mode, NODE_ROLE_SERVER, NUM_NS - 2);
	if (servernode == NULL) {
		rt = -5;
		goto _e_ret;
	}
	servernode->port = local_port;

	u32 task_stksz = (mode == NODE_MODE_SSL)? ATCP_SSL_STACK_SIZE: ATCP_STACK_SIZE;

	if (xTaskCreate(server_start_task, ((const char *) "svr_tsk"), task_stksz, servernode,
	     ATCMD_LWIP_TASK_PRIORITY, &servernode->handletask) != pdPASS) {
		rt = -6;
		goto _e_ret;
	}

	rtw_init_sema(&server_started, 0);

	// Wait for task server_send_task started.
	rtw_down_sema(&server_started);

	// maybe move "OK" to the server_start_task
	at_printf(STR_RESP_OK);

	// Inform task client_send_task we had sent "OK"
	rtw_up_sema(&server_ok_sync);

	rtw_free_sema(&server_started);

	goto __ret;

_e_ret:
	if (servernode) {
		delete_node(servernode);
		servernode = NULL;
	}

__ret:
	if (rt >= 0) {
		// at_printf(STR_RESP_OK);
	} else {
		AT_DBG_MSG(AT_FLAG_LWIP, AT_DBG_ERROR, "\r\n+CIPSERVER: Error %d", rt);
		at_printf(STR_RESP_FAIL);
	}

	return;
}

/* Set/Get Server TimeOut value */
void fATCIPSTO(void* arg) {
	int argc;
	char *argv[MAX_ARGC] = { 0 };
	int sto = 0;

	if (!arg) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	argc = parse_param(arg, argv);
	if (argc < 2 || argv[1] == NULL) {
		at_printf(STR_RESP_FAIL);
		return;
	}

	// Query
	if (*argv[1] == '?') {
		at_printf("+CIPSTO:%d\r\n", sto);
		at_printf(STR_RESP_OK);
		return;
	}

	// Set
	// TODO: empty imp
	sto = atoi(argv[1]);
	at_printf(STR_RESP_OK);
	return;
}





log_item_t at_transport_items[] = {
	{"ATP0", fATP0,},	//query errno if defined
	{"ATPS", fATPS,},	//Create Server
	{"ATPD", fATPD,},	//Close Server/Client connection
	{"ATPC", fATPC,},	//Create Client
	{"ATPT", fATPT,},	//WRITE DATA
	{"ATPR", fATPR,},	//READ DATA
	{"ATPK", fATPK,},	//Auto recv
	{"ATPP", fATPP,},	//PING
	{"ATPI", fATPI,},	//printf connection status
	{"ATPU", fATPU,},	//transparent transmission mode
	{"ATPL", fATPL,},	//lwip auto reconnect setting
	{"AT+CIPDOMAIN", fATCIPDOMAIN},
	{"AT+CIPSTART",  fATCIPSTART},
	{"AT+CIPSEND",   fATCIPSEND},
	{"AT+CIPCLOSE",  fATCIPCLOSE},
	{"AT+CIPDNS",    fATCIPDNS},
	{"AT+CIPSERVERMAXCONN", fATCIPSERVERMAXCONN},
	{"AT+CIPSERVER", fATCIPSERVER},
	{"AT+CIPSTO",    fATCIPSTO},
};

void print_tcpip_at(void *arg)
{
	int index;
	int cmd_len = 0;
	(void) arg;

	cmd_len = sizeof(at_transport_items) / sizeof(at_transport_items[0]);
	for (index = 0; index < cmd_len; index++)
		at_printf("\r\n%s", at_transport_items[index].log_cmd);
}

void at_transport_init(void)
{
	init_node_pool();
	/* mainlist use last linkid/con_id, reserved #0 */
	mainlist = _create_node(-1, -1, NUM_NS - 1);
	log_service_add_table(at_transport_items, sizeof(at_transport_items) / sizeof(at_transport_items[0]));
}

log_module_init(at_transport_init);
