/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_websocket_client_sample, LOG_LEVEL_DBG);

#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/websocket.h>
#include <zephyr/random/rand32.h>
#include <zephyr/shell/shell.h>

#include "ca_certificate.h"

#define SERVER_PORT 8088

#if defined(CONFIG_NET_CONFIG_MY_IPV6_ADDR)
#define SERVER_ADDR6  CONFIG_NET_CONFIG_MY_IPV6_ADDR
#else
#define SERVER_ADDR6 ""
#endif

#if defined(CONFIG_NET_CONFIG_MY_IPV4_ADDR)
#define SERVER_ADDR4  CONFIG_NET_CONFIG_MY_IPV4_ADDR
#else
#define SERVER_ADDR4 ""
#endif

#define MAX_RECV_BUF_LEN	1550
#define EXTRA_BUF_SPACE		30

static uint8_t temp_buf_ipv4[MAX_RECV_BUF_LEN + EXTRA_BUF_SPACE];
static uint8_t temp_buf_ipv6[MAX_RECV_BUF_LEN + EXTRA_BUF_SPACE];

void reset_socket(int *sock) {
	if (*sock >= 0) {
		close(*sock);
		*sock = -1;
	}
}

static int setup_socket(sa_family_t family, const char *host, int port,
			int *sock, struct sockaddr *addr, socklen_t addr_len)
{
	const char *family_str = family == AF_INET ? "IPv4" : "IPv6";
	int ret = 0;

	memset(addr, 0, addr_len);

	if (family == AF_INET) {
		net_sin(addr)->sin_family = AF_INET;
		net_sin(addr)->sin_port = htons(port);
		inet_pton(family, host, &net_sin(addr)->sin_addr);
	} else {
		net_sin6(addr)->sin6_family = AF_INET6;
		net_sin6(addr)->sin6_port = htons(port);
		inet_pton(family, host, &net_sin6(addr)->sin6_addr);
	}

	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)) {
		sec_tag_t sec_tag_list[] = {
			CA_CERTIFICATE_TAG,
		};

		*sock = socket(family, SOCK_STREAM, IPPROTO_TLS_1_2);
		if (*sock >= 0) {
			ret = setsockopt(*sock, SOL_TLS, TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list));
			if (ret < 0) {
				LOG_ERR("Failed to set %s secure option (%d)",
					family_str, -errno);
				reset_socket(sock);
				return -errno;
			}

			ret = setsockopt(*sock, SOL_TLS, TLS_HOSTNAME,
					 TLS_PEER_HOSTNAME,
					 sizeof(TLS_PEER_HOSTNAME));
			if (ret < 0) {
				LOG_ERR("Failed to set %s TLS_HOSTNAME "
					"option (%d)", family_str, -errno);
				reset_socket(sock);
				return -errno;
			}
		}
	} else {
		*sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	}

	if (*sock < 0) {
		LOG_ERR("Failed to create %s HTTP socket (%d)", family_str,
			-errno);
	}

	return ret;
}

static int prepare_socket(sa_family_t family, const char *host, int port,
			  int *sock, struct sockaddr *addr)
{
	int ret;

	ret = setup_socket(family, host, port, sock, addr, sizeof(*addr));
	if (ret < 0 || *sock < 0) {
		return -1;
	}

	ret = zsock_bind(*sock, addr, sizeof(*addr));
	if (ret < 0) {
		LOG_ERR("Failed to bind to remote IPv%d socket on %s:%d",
			family == AF_INET ? 4 : 6, host, port);
		return -errno;
	}

#define MAX_CLIENT_QUEUE	5
	ret = zsock_listen(*sock, MAX_CLIENT_QUEUE);
	if (ret < 0) {
		LOG_ERR("Failed to bind to remote IPv%d socket on %s:%d",
			family == AF_INET ? 4 : 6, host, port);
		ret = -errno;
	}

	return ret;
}

static int accept_cb(int sock, void *user_data)
{
	LOG_INF("Websocket %d for %s accepted.", sock, (char *)user_data);

	return 0;
}

int main(void)
{
	/* Just an example how to set extra headers */
	const char *extra_headers[] = {
		"Origin: http://foobar\r\n",
		NULL
	};
	int sock4 = -1, sock6 = -1;
	int websock4 = -1, websock6 = -1;
	int32_t timeout = SYS_FOREVER_MS;
	struct sockaddr_in6 bind_addr6;
	struct sockaddr_in bind_addr4;
	int ret;

	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)) {
		ret = tls_credential_add(CA_CERTIFICATE_TAG,
					 TLS_CREDENTIAL_CA_CERTIFICATE,
					 ca_certificate,
					 sizeof(ca_certificate));
		if (ret < 0) {
			LOG_ERR("Failed to register public certificate: %d",
				ret);
			k_sleep(K_FOREVER);
		}
	}

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		(void)prepare_socket(AF_INET, SERVER_ADDR4, SERVER_PORT, &sock4,
				    (struct sockaddr *)&bind_addr4);
	}

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		(void)prepare_socket(AF_INET6, SERVER_ADDR6, SERVER_PORT, &sock6,
				     (struct sockaddr *)&bind_addr6);
	}

	if (sock4 < 0 && sock6 < 0) {
		LOG_ERR("Cannot create socket connection.");
		k_sleep(K_FOREVER);
	}

	if (sock4 >= 0 && IS_ENABLED(CONFIG_NET_IPV4)) {
		struct websocket_server srv;

		memset(&srv, 0, sizeof(srv));

		srv.host = SERVER_ADDR4;
		srv.url = "/";
		srv.optional_headers = extra_headers;
		srv.cb = accept_cb;
		srv.tmp_buf = temp_buf_ipv4;
		srv.tmp_buf_len = sizeof(temp_buf_ipv4);

		websock4 = websocket_accept(sock4, &srv, timeout, "IPv4");
		if (websock4 < 0) {
			socklen_t addrlen4 = sizeof(struct sockaddr);
			struct sockaddr_in addr4;
			websocket_sockaddr(sock4, (struct sockaddr *)&addr4,
					   &addrlen4);
			char addr_str[32];
			inet_ntop(addr4.sin_family, &addr4.sin_addr, addr_str,
				  sizeof(addr_str));
			LOG_ERR("Cannot accept from %s:%d", addr_str,
				addr4.sin_port);
			if (sock4 >= 0) {
				close(sock4);
			}
		}
	}

	if (sock6 >= 0 && IS_ENABLED(CONFIG_NET_IPV6)) {
		struct websocket_server srv;

		memset(&srv, 0, sizeof(srv));

		srv.host = SERVER_ADDR6;
		srv.url = "/";
		srv.optional_headers = extra_headers;
		srv.cb = accept_cb;
		srv.tmp_buf = temp_buf_ipv6;
		srv.tmp_buf_len = sizeof(temp_buf_ipv6);

		websock6 = websocket_accept(sock6, &srv, timeout, "IPv6");
		if (websock6 < 0) {
			// char addr_str[32];
			// inet_ntop(addr6.sin6_family, &addr6.sin6_addr, addr_str,
			// 	  sizeof(addr_str));
			// LOG_ERR("Cannot accept from %s:%d", addr_str,
			// 	addr6.sin6_port);
			if (sock6 >= 0) {
				close(sock6);
			}
		}
	}

	if (websock4 < 0 && websock6 < 0) {
		LOG_ERR("No IPv4 or IPv6 connectivity");
		k_sleep(K_FOREVER);
	}

	LOG_INF("Websocket IPv4 %d IPv6 %d", websock4, websock6);
	while (true) {
		k_sleep(K_MSEC(250));
	}

	if (websock4 >= 0) {
		close(websock4);
	}

	if (websock6 >= 0) {
		close(websock6);
	}

	k_sleep(K_FOREVER);
	return 0;
}
