/** @file
 * @brief Websocket client API
 *
 * An API for applications to setup a websocket connections.
 */

/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_websocket, CONFIG_NET_WEBSOCKET_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include <zephyr/sys/fdtable.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_ip.h>
#if defined(CONFIG_POSIX_API)
#include <zephyr/posix/unistd.h>
#include <zephyr/posix/sys/socket.h>
#else
#include <zephyr/net/socket.h>
#endif
#include <zephyr/net/http/client.h>
#include <zephyr/net/websocket.h>

#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/base64.h>
#include <mbedtls/sha1.h>

#include "net_private.h"
#include "sockets_internal.h"
#include "websocket_internal.h"

/* If you want to see the data that is being sent or received,
 * then you can enable debugging and set the following variables to 1.
 * This will print a lot of data so is not enabled by default.
 */
#define HEXDUMP_SENT_PACKETS 0
#define HEXDUMP_RECV_PACKETS 0

#define HTTP_STR	"HTTP"
#define GET_STR		"GET"

#define upgrade_str		"upgrade"
#define websocket_str		"websocket"

#define host_field_str 		"Host:"
#define upgrade_field_str	"Upgrade:"
#define connection_field_str	"Connection:"
#define sec_ws_ver_field_str	"Sec-WebSocket-Version:"
#define sec_ws_key_field_str	"Sec-WebSocket-Key:"

#define MAX_HTTP_HEADER_SIZE	1700

static struct websocket_context contexts[CONFIG_WEBSOCKET_MAX_CONTEXTS];

static struct k_sem contexts_lock;

static const struct socket_op_vtable websocket_fd_op_vtable;

#if defined(CONFIG_NET_TEST)
int verify_sent_and_received_msg(struct msghdr *msg, bool split_msg);
#endif

static const char http_400_bad_req[] = {
	"HTTP/1.1 400 Bad Request\r\n"
	"Content-Type: text/plain\r\n"
	"Content-Length: 11\r\n"
	"\r\n"
	"Bad Request\r\n"
	"\r\n"
};

#if !defined(CONFIG_NET_TEST)
static int sendmsg_all(int sock, const struct msghdr *message, int flags);
#endif

static const char *opcode2str(enum websocket_opcode opcode)
{
	switch (opcode) {
	case WEBSOCKET_OPCODE_DATA_TEXT:
		return "TEXT";
	case WEBSOCKET_OPCODE_DATA_BINARY:
		return "BIN";
	case WEBSOCKET_OPCODE_CONTINUE:
		return "CONT";
	case WEBSOCKET_OPCODE_CLOSE:
		return "CLOSE";
	case WEBSOCKET_OPCODE_PING:
		return "PING";
	case WEBSOCKET_OPCODE_PONG:
		return "PONG";
	default:
		break;
	}

	return NULL;
}

static int websocket_context_ref(struct websocket_context *ctx)
{
	int old_rc = atomic_inc(&ctx->refcount);

	return old_rc + 1;
}

static int websocket_context_unref(struct websocket_context *ctx)
{
	int old_rc = atomic_dec(&ctx->refcount);

	if (old_rc != 1) {
		return old_rc - 1;
	}

	return 0;
}

static inline bool websocket_context_is_used(struct websocket_context *ctx)
{
	NET_ASSERT(ctx);

	return !!atomic_get(&ctx->refcount);
}

static struct websocket_context *websocket_get(void)
{
	struct websocket_context *ctx = NULL;
	int i;

	k_sem_take(&contexts_lock, K_FOREVER);

	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		if (websocket_context_is_used(&contexts[i])) {
			continue;
		}

		websocket_context_ref(&contexts[i]);
		ctx = &contexts[i];
		break;
	}

	k_sem_give(&contexts_lock);

	return ctx;
}

static struct websocket_context *websocket_find(int real_sock)
{
	struct websocket_context *ctx = NULL;
	int i;

	k_sem_take(&contexts_lock, K_FOREVER);

	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		if (!websocket_context_is_used(&contexts[i])) {
			continue;
		}

		if (contexts[i].real_sock != real_sock) {
			continue;
		}

		ctx = &contexts[i];
		break;
	}

	k_sem_give(&contexts_lock);

	return ctx;
}

static void response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	struct websocket_context *ctx = user_data;

	if (final_data == HTTP_DATA_MORE) {
		NET_DBG("[%p] Partial data received (%zd bytes)", ctx,
			rsp->data_len);
		ctx->all_received = false;
	} else if (final_data == HTTP_DATA_FINAL) {
		NET_DBG("[%p] All the data received (%zd bytes)", ctx,
			rsp->data_len);
		ctx->all_received = true;
	}
}

static int on_header_field(struct http_parser *parser, const char *at,
			   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
						struct http_request,
						internal.parser);
	struct websocket_context *ctx = req->internal.user_data;
	const char *ws_accept_str = "Sec-WebSocket-Accept";
	uint16_t len;

	len = strlen(ws_accept_str);
	if (length >= len && strncasecmp(at, ws_accept_str, len) == 0) {
		ctx->sec_accept_present = true;
	}

	if (ctx->http_cb && ctx->http_cb->on_header_field) {
		ctx->http_cb->on_header_field(parser, at, length);
	}

	return 0;
}

#define MAX_SEC_ACCEPT_LEN 32

static int on_header_value(struct http_parser *parser, const char *at,
			   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
						struct http_request,
						internal.parser);
	struct websocket_context *ctx = req->internal.user_data;
	char str[MAX_SEC_ACCEPT_LEN];

	if (ctx->sec_accept_present) {
		int ret;
		size_t olen;

		ctx->sec_accept_ok = false;
		ctx->sec_accept_present = false;

		ret = base64_encode(str, sizeof(str) - 1, &olen,
				    ctx->sec_accept_key,
				    WS_SHA1_OUTPUT_LEN);
		if (ret == 0) {
			if (strncmp(at, str, length)) {
				NET_DBG("[%p] Security keys do not match "
					"%s vs %s", ctx, str, at);
			} else {
				ctx->sec_accept_ok = true;
			}
		}
	}

	if (ctx->http_cb && ctx->http_cb->on_header_value) {
		ctx->http_cb->on_header_value(parser, at, length);
	}

	return 0;
}

int websocket_connect(int sock, struct websocket_request *wreq,
		      int32_t timeout, void *user_data)
{
	/* This is the expected Sec-WebSocket-Accept key. We are storing a
	 * pointer to this in ctx but the value is only used for the duration
	 * of this function call so there is no issue even if this variable
	 * is allocated from stack.
	 */
	uint8_t sec_accept_key[WS_SHA1_OUTPUT_LEN];
	struct http_parser_settings http_parser_settings;
	struct websocket_context *ctx;
	struct http_request req;
	int ret, fd, key_len;
	size_t olen;
	char key_accept[MAX_SEC_ACCEPT_LEN + sizeof(WS_MAGIC)];
	uint32_t rnd_value = sys_rand32_get();
	char sec_ws_key[] =
		"Sec-WebSocket-Key: 0123456789012345678901==\r\n";
	char *headers[] = {
		sec_ws_key,
		"Upgrade: websocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Version: 13\r\n",
		NULL
	};

	fd = -1;

	if (sock < 0 || wreq == NULL || wreq->host == NULL ||
	    wreq->url == NULL) {
		return -EINVAL;
	}

	ctx = websocket_find(sock);
	if (ctx) {
		NET_DBG("[%p] Websocket for sock %d already exists!", ctx,
			sock);
		return -EEXIST;
	}

	ctx = websocket_get();
	if (!ctx) {
		return -ENOENT;
	}

	ctx->real_sock = sock;
	ctx->recv_buf.buf = wreq->tmp_buf;
	ctx->recv_buf.size = wreq->tmp_buf_len;
	ctx->sec_accept_key = sec_accept_key;
	ctx->http_cb = wreq->http_cb;

	mbedtls_sha1((const unsigned char *)&rnd_value, sizeof(rnd_value),
			 sec_accept_key);

	ret = base64_encode(sec_ws_key + sizeof("Sec-Websocket-Key: ") - 1,
			    sizeof(sec_ws_key) -
					sizeof("Sec-Websocket-Key: "),
			    &olen, sec_accept_key,
			    /* We are only interested in 16 first bytes so
			     * subtract 4 from the SHA-1 length
			     */
			    sizeof(sec_accept_key) - 4);
	if (ret) {
		NET_DBG("[%p] Cannot encode base64 (%d)", ctx, ret);
		goto out;
	}

	if ((olen + sizeof("Sec-Websocket-Key: ") + 2) > sizeof(sec_ws_key)) {
		NET_DBG("[%p] Too long message (%zd > %zd)", ctx,
			olen + sizeof("Sec-Websocket-Key: ") + 2,
			sizeof(sec_ws_key));
		ret = -EMSGSIZE;
		goto out;
	}

	memcpy(sec_ws_key + sizeof("Sec-Websocket-Key: ") - 1 + olen,
	       HTTP_CRLF, sizeof(HTTP_CRLF));

	memset(&req, 0, sizeof(req));

	req.method = HTTP_GET;
	req.url = wreq->url;
	req.host = wreq->host;
	req.protocol = "HTTP/1.1";
	req.header_fields = (const char **)headers;
	req.optional_headers_cb = wreq->optional_headers_cb;
	req.optional_headers = wreq->optional_headers;
	req.response = response_cb;
	req.http_cb = &http_parser_settings;
	req.recv_buf = wreq->tmp_buf;
	req.recv_buf_len = wreq->tmp_buf_len;

	/* We need to catch the Sec-WebSocket-Accept field in order to verify
	 * that it contains the stuff that we sent in Sec-WebSocket-Key field
	 * so setup HTTP callbacks so that we will get the needed fields.
	 */
	if (ctx->http_cb) {
		memcpy(&http_parser_settings, ctx->http_cb,
		       sizeof(http_parser_settings));
	} else {
		memset(&http_parser_settings, 0, sizeof(http_parser_settings));
	}

	http_parser_settings.on_header_field = on_header_field;
	http_parser_settings.on_header_value = on_header_value;

	/* Pre-calculate the expected Sec-Websocket-Accept field */
	key_len = MIN(sizeof(key_accept) - 1, olen);
	strncpy(key_accept, sec_ws_key + sizeof("Sec-Websocket-Key: ") - 1,
		key_len);

	olen = MIN(sizeof(key_accept) - 1 - key_len, sizeof(WS_MAGIC) - 1);
	strncpy(key_accept + key_len, WS_MAGIC, olen);

	/* This SHA-1 value is then checked when we receive the response */
	mbedtls_sha1(key_accept, olen + key_len, sec_accept_key);

	ret = http_client_req(sock, &req, timeout, ctx);
	if (ret < 0) {
		NET_DBG("[%p] Cannot connect to Websocket host %s", ctx,
			wreq->host);
		ret = -ECONNABORTED;
		goto out;
	}

	if (!(ctx->all_received && ctx->sec_accept_ok)) {
		NET_DBG("[%p] WS handshake failed (%d/%d)", ctx,
			ctx->all_received, ctx->sec_accept_ok);
		ret = -ECONNABORTED;
		goto out;
	}

	ctx->user_data = user_data;

	fd = z_reserve_fd();
	if (fd < 0) {
		ret = -ENOSPC;
		goto out;
	}

	ctx->sock = fd;
	z_finalize_fd(fd, ctx,
		      (const struct fd_op_vtable *)&websocket_fd_op_vtable);

	/* Call the user specified callback and if it accepts the connection
	 * then continue.
	 */
	if (wreq->cb) {
		ret = wreq->cb(fd, &req, user_data);
		if (ret < 0) {
			NET_DBG("[%p] Connection aborted (%d)", ctx, ret);
			goto out;
		}
	}

	NET_DBG("[%p] WS connection to peer established (fd %d)", ctx, fd);

	/* We will re-use the temp buffer in receive function if needed but
	 * in order that to work the amount of data in buffer must be set to 0
	 */
	ctx->recv_buf.count = 0;

	/* Init parser FSM */
	ctx->parser_state = WEBSOCKET_PARSER_STATE_OPCODE;

	return fd;

out:
	if (fd >= 0) {
		(void)close(fd);
	}

	websocket_context_unref(ctx);
	return ret;
}

static int websocket_server_http_handshake(struct websocket_server *srv,
					   struct websocket_context *ctx)
{
	int ret = 0;
	static ssize_t conn_cnt = 0;

	websocket_http_handshake_header *hh = &ctx->hs_header;
	memset(hh, 0, sizeof(websocket_http_handshake_header));

	while(true) {
		ret = zsock_recv(ctx->real_sock, ctx->recv_buf.buf,
				 ctx->recv_buf.size, 0);
		if (ret < 0) {
			LOG_ERR("Failed to recieve on socket %d with error: %d",
				ctx->real_sock, errno);
			zsock_close(ctx->real_sock);
			return -errno;
		}

		// Parse http handshake:
		websocket_parse_client_http_handshake(
			(const char*)ctx->recv_buf.buf, hh);

		// Interpret http request:

		conn_cnt++;  // increase connection counter if succeed
		break;  // ToDo: must be covered by final body check!
	}

	// Send http 400 bad request:
	struct msghdr msg;
	struct iovec msg_iov[1];
	memset(&msg, 0, sizeof(struct msghdr));

	msg_iov[0].iov_base = (char*)http_400_bad_req;
	msg_iov[0].iov_len = ARRAY_SIZE(http_400_bad_req) - 1;

	msg.msg_iov = msg_iov;
	msg.msg_iovlen = ARRAY_SIZE(msg_iov);

	ret = sendmsg_all(ctx->real_sock, &msg, MSG_WAITALL);

	return ret;
}

int websocket_accept(int sock, struct websocket_server *srv, int32_t timeout,
		     void *user_data)
{
	int ret = 0;
	const int nfds = 1;
	struct zsock_pollfd fds;
	struct websocket_context *ctx;

	fds.events = ZSOCK_POLLIN;

	if (sock < 0 || srv == NULL || srv->host == NULL || srv->url == NULL) {
		return -EINVAL;
	}

	ctx = websocket_find(sock);
	if (ctx) {
		NET_DBG("[%p] Websocket for sock %d already exists!", ctx,
			sock);
		return -EEXIST;
	}

	ctx = websocket_get();
	if (!ctx) {
		return -ENOENT;
	}

	// if(srv->host != NULL) {
	// 	// ToDo: No handshake shall be done by this server - just return new
	// 	// Websocket (RFC6455, p.20, section 4.2)
	// 	// ToDo: define proper fd and return
	// 	LOG_DBG("---> srv->host is not NULL exit with fd: %d", fd);
	// 	return fd;
	// }

	ret = zsock_poll(&fds, nfds, timeout);
	if (ret < 0) {
		LOG_ERR("poll read event error: %d", errno);
		zsock_close(fds.fd);
		return -errno;
	}

	if ((fds.revents & ZSOCK_POLLERR) || (fds.revents & ZSOCK_POLLNVAL)) {
		LOG_ERR("Receiver socket poll error: %d", errno);
		zsock_close(sock);
		return -errno;
	}

	ctx->addrlen = sizeof(struct sockaddr);
	fds.fd = zsock_accept(sock, (struct sockaddr *)&ctx->client_addr, &ctx->addrlen);
	if (fds.fd < 0) {
		LOG_ERR("Receiver accept error: %d", -errno);
		zsock_close(sock);
		return -errno;
	}

	ctx->real_sock = fds.fd;
	ctx->recv_buf.buf = srv->tmp_buf;
	ctx->recv_buf.size = srv->tmp_buf_len;

	ret = websocket_server_http_handshake(srv, ctx);

	return -1;  // ToDo: use later fds.fd;
}

void websocket_sockaddr(int sock, struct sockaddr* addr, socklen_t *addrlen)
{
	struct websocket_context* ctx = websocket_find(sock);
	k_sem_take(&contexts_lock, K_FOREVER);
	memcpy((void*)addrlen, (void*)&ctx->addrlen, sizeof(socklen_t));
	memcpy((void*)addr, (void*)&ctx->client_addr, sizeof(struct sockaddr));
	k_sem_give(&contexts_lock);
}

int websocket_disconnect(int ws_sock)
{
	return close(ws_sock);
}

static int websocket_interal_disconnect(struct websocket_context *ctx)
{
	int ret;

	if (ctx == NULL) {
		return -ENOENT;
	}

	NET_DBG("[%p] Disconnecting", ctx);

	ret = websocket_send_msg(ctx->sock, NULL, 0, WEBSOCKET_OPCODE_CLOSE,
				 true, true, SYS_FOREVER_MS);
	if (ret < 0) {
		NET_ERR("[%p] Failed to send close message (err %d).", ctx, ret);
	}

	websocket_context_unref(ctx);

	return ret;
}

static int websocket_close_vmeth(void *obj)
{
	struct websocket_context *ctx = obj;
	int ret;

	ret = websocket_interal_disconnect(ctx);
	if (ret < 0) {
		NET_DBG("[%p] Cannot close (%d)", obj, ret);

		errno = -ret;
		return -1;
	}

	return ret;
}

static inline int websocket_poll_offload(struct zsock_pollfd *fds, int nfds,
					 int timeout)
{
	int fd_backup[CONFIG_NET_SOCKETS_POLL_MAX];
	const struct fd_op_vtable *vtable;
	void *ctx;
	int ret = 0;
	int i;

	/* Overwrite websocket file descriptors with underlying ones. */
	for (i = 0; i < nfds; i++) {
		fd_backup[i] = fds[i].fd;

		ctx = z_get_fd_obj(fds[i].fd,
				   (const struct fd_op_vtable *)
						     &websocket_fd_op_vtable,
				   0);
		if (ctx == NULL) {
			continue;
		}

		fds[i].fd = ((struct websocket_context *)ctx)->real_sock;
	}

	/* Get offloaded sockets vtable. */
	ctx = z_get_fd_obj_and_vtable(fds[0].fd,
				      (const struct fd_op_vtable **)&vtable,
				      NULL);
	if (ctx == NULL) {
		errno = EINVAL;
		ret = -1;
		goto exit;
	}

	ret = z_fdtable_call_ioctl(vtable, ctx, ZFD_IOCTL_POLL_OFFLOAD,
				   fds, nfds, timeout);

exit:
	/* Restore original fds. */
	for (i = 0; i < nfds; i++) {
		fds[i].fd = fd_backup[i];
	}

	return ret;
}

static int websocket_ioctl_vmeth(void *obj, unsigned int request, va_list args)
{
	struct websocket_context *ctx = obj;

	switch (request) {
	case ZFD_IOCTL_POLL_OFFLOAD: {
		struct zsock_pollfd *fds;
		int nfds;
		int timeout;

		fds = va_arg(args, struct zsock_pollfd *);
		nfds = va_arg(args, int);
		timeout = va_arg(args, int);

		return websocket_poll_offload(fds, nfds, timeout);
	}

	case ZFD_IOCTL_SET_LOCK:
		/* Ignore, don't want to overwrite underlying socket lock. */
		return 0;

	default: {
		const struct fd_op_vtable *vtable;
		void *core_obj;

		core_obj = z_get_fd_obj_and_vtable(
				ctx->real_sock,
				(const struct fd_op_vtable **)&vtable,
				NULL);
		if (core_obj == NULL) {
			errno = EBADF;
			return -1;
		}

		/* Pass the call to the core socket implementation. */
		return vtable->ioctl(core_obj, request, args);
	}
	}

	return 0;
}

#if !defined(CONFIG_NET_TEST)
static int sendmsg_all(int sock, const struct msghdr *message, int flags)
{
	int ret, i;
	size_t offset = 0;
	size_t total_len = 0;

	for (i = 0; i < message->msg_iovlen; i++) {
		total_len += message->msg_iov[i].iov_len;
	}

	while (offset < total_len) {
		ret = zsock_sendmsg(sock, message, flags);
		if (ret < 0) {
			return -errno;
		}

		offset += ret;
		if (offset >= total_len) {
			break;
		}

		/* Update msghdr for the next iteration. */
		for (i = 0; i < message->msg_iovlen; i++) {
			if (ret < message->msg_iov[i].iov_len) {
				message->msg_iov[i].iov_len -= ret;
				message->msg_iov[i].iov_base =
					(uint8_t *)message->msg_iov[i].iov_base + ret;
				break;
			}

			ret -= message->msg_iov[i].iov_len;
			message->msg_iov[i].iov_len = 0;
		}
	}

	return total_len;
}
#endif /* !defined(CONFIG_NET_TEST) */

static int websocket_prepare_and_send(struct websocket_context *ctx,
				      uint8_t *header, size_t header_len,
				      uint8_t *payload, size_t payload_len,
				      int32_t timeout)
{
	struct iovec io_vector[2];
	struct msghdr msg;

	io_vector[0].iov_base = header;
	io_vector[0].iov_len = header_len;
	io_vector[1].iov_base = payload;
	io_vector[1].iov_len = payload_len;

	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = io_vector;
	msg.msg_iovlen = ARRAY_SIZE(io_vector);

	if (HEXDUMP_SENT_PACKETS) {
		LOG_HEXDUMP_DBG(header, header_len, "Header");
		if ((payload != NULL) && (payload_len > 0)) {
			LOG_HEXDUMP_DBG(payload, payload_len, "Payload");
		} else {
			LOG_DBG("No payload");
		}
	}

#if defined(CONFIG_NET_TEST)
	/* Simulate a case where the payload is split to two. The unit test
	 * does not set mask bit in this case.
	 */
	return verify_sent_and_received_msg(&msg, !(header[1] & BIT(7)));
#else
	k_timeout_t tout = K_FOREVER;

	if (timeout != SYS_FOREVER_MS) {
		tout = K_MSEC(timeout);
	}

	return sendmsg_all(ctx->real_sock, &msg,
			   K_TIMEOUT_EQ(tout, K_NO_WAIT) ? MSG_DONTWAIT : 0);
#endif /* CONFIG_NET_TEST */
}

int websocket_send_msg(int ws_sock, const uint8_t *payload, size_t payload_len,
		       enum websocket_opcode opcode, bool mask, bool final,
		       int32_t timeout)
{
	struct websocket_context *ctx;
	uint8_t header[MAX_HEADER_LEN], hdr_len = 2;
	uint8_t *data_to_send = (uint8_t *)payload;
	int ret;

	if (opcode != WEBSOCKET_OPCODE_DATA_TEXT &&
	    opcode != WEBSOCKET_OPCODE_DATA_BINARY &&
	    opcode != WEBSOCKET_OPCODE_CONTINUE &&
	    opcode != WEBSOCKET_OPCODE_CLOSE &&
	    opcode != WEBSOCKET_OPCODE_PING &&
	    opcode != WEBSOCKET_OPCODE_PONG) {
		return -EINVAL;
	}

	ctx = z_get_fd_obj(ws_sock, NULL, 0);
	if (ctx == NULL) {
		return -EBADF;
	}

#if !defined(CONFIG_NET_TEST)
	/* Websocket unit test does not use context from pool but allocates
	 * its own, hence skip the check.
	 */

	if (!PART_OF_ARRAY(contexts, ctx)) {
		return -ENOENT;
	}
#endif /* !defined(CONFIG_NET_TEST) */

	NET_DBG("[%p] Len %zd %s/%d/%s", ctx, payload_len, opcode2str(opcode),
		mask, final ? "final" : "more");

	memset(header, 0, sizeof(header));

	/* Is this the last packet? */
	header[0] = final ? BIT(7) : 0;

	/* Text, binary, ping, pong or close ? */
	header[0] |= opcode;

	/* Masking */
	header[1] = mask ? BIT(7) : 0;

	if (payload_len < 126) {
		header[1] |= payload_len;
	} else if (payload_len < 65536) {
		header[1] |= 126;
		header[2] = payload_len >> 8;
		header[3] = payload_len;
		hdr_len += 2;
	} else {
		header[1] |= 127;
		header[2] = 0;
		header[3] = 0;
		header[4] = 0;
		header[5] = 0;
		header[6] = payload_len >> 24;
		header[7] = payload_len >> 16;
		header[8] = payload_len >> 8;
		header[9] = payload_len;
		hdr_len += 8;
	}

	/* Add masking value if needed */
	if (mask) {
		int i;

		ctx->masking_value = sys_rand32_get();

		header[hdr_len++] |= ctx->masking_value >> 24;
		header[hdr_len++] |= ctx->masking_value >> 16;
		header[hdr_len++] |= ctx->masking_value >> 8;
		header[hdr_len++] |= ctx->masking_value;

		if ((payload != NULL) && (payload_len > 0)) {
			data_to_send = k_malloc(payload_len);
			if (!data_to_send) {
				return -ENOMEM;
			}

			memcpy(data_to_send, payload, payload_len);

			for (i = 0; i < payload_len; i++) {
				data_to_send[i] ^= ctx->masking_value >> (8 * (3 - i % 4));
			}
		}
	}

	ret = websocket_prepare_and_send(ctx, header, hdr_len,
					 data_to_send, payload_len, timeout);
	if (ret < 0) {
		NET_DBG("Cannot send ws msg (%d)", -errno);
		goto quit;
	}

quit:
	if (data_to_send != payload) {
		k_free(data_to_send);
	}

	/* Do no math with 0 and error codes */
	if (ret <= 0) {
		return ret;
	}

	return ret - hdr_len;
}

static uint32_t websocket_opcode2flag(uint8_t data)
{
	switch (data & 0x0f) {
	case WEBSOCKET_OPCODE_DATA_TEXT:
		return WEBSOCKET_FLAG_TEXT;
	case WEBSOCKET_OPCODE_DATA_BINARY:
		return WEBSOCKET_FLAG_BINARY;
	case WEBSOCKET_OPCODE_CLOSE:
		return WEBSOCKET_FLAG_CLOSE;
	case WEBSOCKET_OPCODE_PING:
		return WEBSOCKET_FLAG_PING;
	case WEBSOCKET_OPCODE_PONG:
		return WEBSOCKET_FLAG_PONG;
	default:
		break;
	}
	return 0;
}

static int websocket_parse(struct websocket_context *ctx, struct websocket_buffer *payload)
{
	int len;
	uint8_t data;
	size_t parsed_count = 0;

	do {
		if (parsed_count >= ctx->recv_buf.count) {
			return parsed_count;
		}
		if (ctx->parser_state != WEBSOCKET_PARSER_STATE_PAYLOAD) {
			data = ctx->recv_buf.buf[parsed_count++];

			switch (ctx->parser_state) {
			case WEBSOCKET_PARSER_STATE_OPCODE:
				ctx->message_type = websocket_opcode2flag(data);
				if ((data & 0x80) != 0) {
					ctx->message_type |= WEBSOCKET_FLAG_FINAL;
				}
				ctx->parser_state = WEBSOCKET_PARSER_STATE_LENGTH;
				break;
			case WEBSOCKET_PARSER_STATE_LENGTH:
				ctx->masked = (data & 0x80) != 0;
				len = data & 0x7f;
				if (len < 126) {
					ctx->message_len = len;
					if (ctx->masked) {
						ctx->masking_value = 0;
						ctx->parser_remaining = 4;
						ctx->parser_state = WEBSOCKET_PARSER_STATE_MASK;
					} else {
						ctx->parser_remaining = ctx->message_len;
						ctx->parser_state =
							(ctx->parser_remaining == 0)
								? WEBSOCKET_PARSER_STATE_OPCODE
								: WEBSOCKET_PARSER_STATE_PAYLOAD;
					}
				} else {
					ctx->message_len = 0;
					ctx->parser_remaining = (len < 127) ? 2 : 8;
					ctx->parser_state = WEBSOCKET_PARSER_STATE_EXT_LEN;
				}
				break;
			case WEBSOCKET_PARSER_STATE_EXT_LEN:
				ctx->parser_remaining--;
				ctx->message_len |= ((uint64_t)data << (ctx->parser_remaining * 8));
				if (ctx->parser_remaining == 0) {
					if (ctx->masked) {
						ctx->masking_value = 0;
						ctx->parser_remaining = 4;
						ctx->parser_state = WEBSOCKET_PARSER_STATE_MASK;
					} else {
						ctx->parser_remaining = ctx->message_len;
						ctx->parser_state = WEBSOCKET_PARSER_STATE_PAYLOAD;
					}
				}
				break;
			case WEBSOCKET_PARSER_STATE_MASK:
				ctx->parser_remaining--;
				ctx->masking_value |= (data << (ctx->parser_remaining * 8));
				if (ctx->parser_remaining == 0) {
					if (ctx->message_len == 0) {
						ctx->parser_remaining = 0;
						ctx->parser_state = WEBSOCKET_PARSER_STATE_OPCODE;
					} else {
						ctx->parser_remaining = ctx->message_len;
						ctx->parser_state = WEBSOCKET_PARSER_STATE_PAYLOAD;
					}
				}
				break;
			default:
				return -EFAULT;
			}

#if (LOG_LEVEL >= LOG_LEVEL_DBG)
			if ((ctx->parser_state == WEBSOCKET_PARSER_STATE_PAYLOAD) ||
			    ((ctx->parser_state == WEBSOCKET_PARSER_STATE_OPCODE) &&
			     (ctx->message_len == 0))) {
				NET_DBG("[%p] %smasked, mask 0x%08x, type 0x%02x, msg %zd", ctx,
					ctx->masked ? "" : "un",
					ctx->masked ? ctx->masking_value : 0, ctx->message_type,
					(size_t)ctx->message_len);
			}
#endif
		} else {
			size_t remaining_in_recv_buf = ctx->recv_buf.count - parsed_count;
			size_t payload_in_recv_buf =
				MIN(remaining_in_recv_buf, ctx->parser_remaining);
			size_t free_in_payload_buf = payload->size - payload->count;
			size_t ready_to_copy = MIN(payload_in_recv_buf, free_in_payload_buf);

			if (free_in_payload_buf == 0) {
				break;
			}

			memcpy(&payload->buf[payload->count], &ctx->recv_buf.buf[parsed_count],
			       ready_to_copy);
			parsed_count += ready_to_copy;
			payload->count += ready_to_copy;
			ctx->parser_remaining -= ready_to_copy;
			if (ctx->parser_remaining == 0) {
				ctx->parser_remaining = 0;
				ctx->parser_state = WEBSOCKET_PARSER_STATE_OPCODE;
			}
		}

	} while (ctx->parser_state != WEBSOCKET_PARSER_STATE_OPCODE);

	return parsed_count;
}

#if !defined(CONFIG_NET_TEST)
static int wait_rx(int sock, int timeout)
{
	struct zsock_pollfd fds = {
		.fd = sock,
		.events = ZSOCK_POLLIN,
	};
	int ret;

	ret = zsock_poll(&fds, 1, timeout);
	if (ret < 0) {
		return ret;
	}

	if (ret == 0) {
		/* Timeout */
		return -EAGAIN;
	}

	if (fds.revents & ZSOCK_POLLNVAL) {
		return -EBADF;
	}

	if (fds.revents & ZSOCK_POLLERR) {
		return -EIO;
	}

	return 0;
}

static int timeout_to_ms(k_timeout_t *timeout)
{
	if (K_TIMEOUT_EQ(*timeout, K_NO_WAIT)) {
		return 0;
	} else if (K_TIMEOUT_EQ(*timeout, K_FOREVER)) {
		return SYS_FOREVER_MS;
	} else {
		return k_ticks_to_ms_floor32(timeout->ticks);
	}
}

#endif /* !defined(CONFIG_NET_TEST) */

int websocket_recv_msg(int ws_sock, uint8_t *buf, size_t buf_len,
		       uint32_t *message_type, uint64_t *remaining, int32_t timeout)
{
	struct websocket_context *ctx;
	int ret;
	k_timepoint_t end;
	k_timeout_t tout = K_FOREVER;
	struct websocket_buffer payload = {.buf = buf, .size = buf_len, .count = 0};

	if (timeout != SYS_FOREVER_MS) {
		tout = K_MSEC(timeout);
	}

	if ((buf == NULL) || (buf_len == 0)) {
		return -EINVAL;
	}

	end = sys_timepoint_calc(tout);

#if defined(CONFIG_NET_TEST)
	struct test_data *test_data = z_get_fd_obj(ws_sock, NULL, 0);

	if (test_data == NULL) {
		return -EBADF;
	}

	ctx = test_data->ctx;
#else
	ctx = z_get_fd_obj(ws_sock, NULL, 0);
	if (ctx == NULL) {
		return -EBADF;
	}

	if (!PART_OF_ARRAY(contexts, ctx)) {
		return -ENOENT;
	}
#endif /* CONFIG_NET_TEST */

	do {
		size_t parsed_count;

		if (ctx->recv_buf.count == 0) {
#if defined(CONFIG_NET_TEST)
			size_t input_len = MIN(ctx->recv_buf.size,
					       test_data->input_len - test_data->input_pos);

			if (input_len > 0) {
				memcpy(ctx->recv_buf.buf,
				       &test_data->input_buf[test_data->input_pos], input_len);
				test_data->input_pos += input_len;
				ret = input_len;
			} else {
				/* emulate timeout */
				ret = -EAGAIN;
			}
#else
			tout = sys_timepoint_timeout(end);

			ret = wait_rx(ctx->real_sock, timeout_to_ms(&tout));
			if (ret == 0) {
				ret = recv(ctx->real_sock, ctx->recv_buf.buf,
					   ctx->recv_buf.size, MSG_DONTWAIT);
				if (ret < 0) {
					ret = -errno;
				}
			}
#endif /* CONFIG_NET_TEST */

			if (ret < 0) {
				if ((ret == -EAGAIN) && (payload.count > 0)) {
					/* go to unmasking */
					break;
				}
				return ret;
			}

			if (ret == 0) {
				/* Socket closed */
				return -ENOTCONN;
			}

			ctx->recv_buf.count = ret;

			NET_DBG("[%p] Received %d bytes", ctx, ret);
		}

		ret = websocket_parse(ctx, &payload);
		if (ret < 0) {
			return ret;
		}
		parsed_count = ret;

		if ((ctx->parser_state == WEBSOCKET_PARSER_STATE_OPCODE) ||
		    (payload.count >= payload.size)) {
			if (remaining != NULL) {
				*remaining = ctx->parser_remaining;
			}
			if (message_type != NULL) {
				*message_type = ctx->message_type;
			}

			size_t left = ctx->recv_buf.count - parsed_count;

			if (left > 0) {
				memmove(ctx->recv_buf.buf, &ctx->recv_buf.buf[parsed_count], left);
			}
			ctx->recv_buf.count = left;
			break;
		}

		ctx->recv_buf.count -= parsed_count;

	} while (true);

	/* Unmask the data */
	if (ctx->masked) {
		uint8_t *mask_as_bytes = (uint8_t *)&ctx->masking_value;
		size_t data_buf_offset = ctx->message_len - ctx->parser_remaining - payload.count;

		for (size_t i = 0; i < payload.count; i++) {
			size_t m = data_buf_offset % 4;

			payload.buf[i] ^= mask_as_bytes[3 - m];
			data_buf_offset++;
		}
	}

	return payload.count;
}

static int websocket_send(struct websocket_context *ctx, const uint8_t *buf,
			  size_t buf_len, int32_t timeout)
{
	int ret;

	NET_DBG("[%p] Sending %zd bytes", ctx, buf_len);

	ret = websocket_send_msg(ctx->sock, buf, buf_len,
				 WEBSOCKET_OPCODE_DATA_TEXT,
				 true, true, timeout);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	NET_DBG("[%p] Sent %d bytes", ctx, ret);

	return ret;
}

static int websocket_recv(struct websocket_context *ctx, uint8_t *buf,
			  size_t buf_len, int32_t timeout)
{
	uint32_t message_type;
	uint64_t remaining;
	int ret;

	NET_DBG("[%p] Waiting data, buf len %zd bytes", ctx, buf_len);

	/* TODO: add support for recvmsg() so that we could return the
	 *       websocket specific information in ancillary data.
	 */
	ret = websocket_recv_msg(ctx->sock, buf, buf_len, &message_type,
				 &remaining, timeout);
	if (ret < 0) {
		if (ret == -ENOTCONN) {
			ret = 0;
		} else {
			errno = -ret;
			return -1;
		}
	}

	NET_DBG("[%p] Received %d bytes", ctx, ret);

	return ret;
}

static ssize_t websocket_read_vmeth(void *obj, void *buffer, size_t count)
{
	return (ssize_t)websocket_recv(obj, buffer, count, SYS_FOREVER_MS);
}

static ssize_t websocket_write_vmeth(void *obj, const void *buffer,
				     size_t count)
{
	return (ssize_t)websocket_send(obj, buffer, count, SYS_FOREVER_MS);
}

static ssize_t websocket_sendto_ctx(void *obj, const void *buf, size_t len,
				    int flags,
				    const struct sockaddr *dest_addr,
				    socklen_t addrlen)
{
	struct websocket_context *ctx = obj;
	int32_t timeout = SYS_FOREVER_MS;

	if (flags & ZSOCK_MSG_DONTWAIT) {
		timeout = 0;
	}

	ARG_UNUSED(dest_addr);
	ARG_UNUSED(addrlen);

	return (ssize_t)websocket_send(ctx, buf, len, timeout);
}

static ssize_t websocket_recvfrom_ctx(void *obj, void *buf, size_t max_len,
				      int flags, struct sockaddr *src_addr,
				      socklen_t *addrlen)
{
	struct websocket_context *ctx = obj;
	int32_t timeout = SYS_FOREVER_MS;

	if (flags & ZSOCK_MSG_DONTWAIT) {
		timeout = 0;
	}

	ARG_UNUSED(src_addr);
	ARG_UNUSED(addrlen);

	return (ssize_t)websocket_recv(ctx, buf, max_len, timeout);
}

static const struct socket_op_vtable websocket_fd_op_vtable = {
	.fd_vtable = {
		.read = websocket_read_vmeth,
		.write = websocket_write_vmeth,
		.close = websocket_close_vmeth,
		.ioctl = websocket_ioctl_vmeth,
	},
	.sendto = websocket_sendto_ctx,
	.recvfrom = websocket_recvfrom_ctx,
};

void websocket_context_foreach(websocket_context_cb_t cb, void *user_data)
{
	int i;

	k_sem_take(&contexts_lock, K_FOREVER);

	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		if (!websocket_context_is_used(&contexts[i])) {
			continue;
		}

		k_mutex_lock(&contexts[i].lock, K_FOREVER);

		cb(&contexts[i], user_data);

		k_mutex_unlock(&contexts[i].lock);
	}

	k_sem_give(&contexts_lock);
}

void websocket_init(void)
{
	k_sem_init(&contexts_lock, 1, K_SEM_MAX_LIMIT);
}

void str_tolower(char* str)
{
	for (int i = 0; str[i] != '\0'; i++) {
		str[i] = tolower(str[i]);
	}
}

void copy_substr(char* src, char* dst, size_t dst_len, const char end_char) {
	const char* sub_str_end = strchr(src + 1, end_char);
	const size_t sub_str_len = sub_str_end - src;
	memcpy(dst, src, MIN(sub_str_len, dst_len));
}

bool find_field_lower(char* str, size_t field_name_len,
			const char* field_val, size_t field_val_len) {
	const size_t field_name_offset = field_name_len;
	const size_t field_len = MAX(strlen(str + field_name_offset),
					field_val_len);
	str_tolower(str + field_name_offset);
	int ret = -1;
	void* p = str + field_name_offset;
	while(ret != 0) {
	ret = strncmp(p, field_val, field_len);
	p = UINT_TO_POINTER(POINTER_TO_UINT(p) + 1);
	if((*(char*)p) == '\n' || (*(char*)p) == '\r' || p == NULL) {
		break;
	}
	}
	return ret == 0;
}

size_t websocket_parse_client_http_handshake(const char *request,
				websocket_http_handshake_header *hh)
{
	size_t bytes_cnt = 0;
	char buffer[MAX_HTTP_HEADER_SIZE] = {0};
	const char* last_char = strstr(request, "\r\n\r\n");
	const size_t header_len = last_char - request;
	char* saveptr = NULL;

	if (header_len >= MAX_HTTP_HEADER_SIZE) {
		errno = -ENOBUFS;
		LOG_ERR("Header size exceeds maximum allowed size of %d",
			MAX_HTTP_HEADER_SIZE);
		return bytes_cnt;
	}

	strncpy(buffer, request, header_len);

	char *line = strtok_r(buffer, "\r\n", &saveptr);
	bytes_cnt += strlen(line) + sizeof("\r\n") - 1;
	while (line != NULL) {
		// LOG_DBG("bytes_cnt: %d, line: [%s] saveptr: [%s]",
		// 	bytes_cnt, line, saveptr);
		if (strncmp(line, GET_STR, sizeof(GET_STR) - 1) == 0) {
			// Parse path:
			copy_substr(line + strlen(GET_STR) + 1, hh->path,
				    sizeof(hh->path), ' ');

			// Parse HTTP version:
			const char* version = line + strlen(GET_STR) + 1
					+ strlen(hh->path) + 1
					+ strlen(HTTP_STR) + 1;
			hh->http_version_major = atoi(version);
			hh->http_version_minor = atoi(strchr(version, '.') + 1);
		} else if (strncmp(line, upgrade_field_str,
				   sizeof(upgrade_field_str) - 1) == 0) {
			hh->upgrade_websocket = find_field_lower(line,
							sizeof(upgrade_field_str),
							websocket_str,
							sizeof(websocket_str) - 1);
		} else if (strncmp(line, connection_field_str,
				   sizeof(connection_field_str) - 1) == 0) {
			hh->connection_upgrade = find_field_lower(line,
							sizeof(connection_field_str),
							upgrade_str,
							sizeof(upgrade_str) - 1);
		} else if (strncmp(line, sec_ws_ver_field_str,
				   sizeof(sec_ws_ver_field_str) - 1) == 0) {
			hh->sec_websocket_version = atoi(line
						+ sizeof(sec_ws_ver_field_str));
		} else if (strncmp(line, host_field_str,
				   sizeof(host_field_str) - 1) == 0) {
			copy_substr(line + sizeof(host_field_str), hh->host,
				    sizeof(hh->host), ' ');
		} else if (strncmp(line, sec_ws_key_field_str,
				   sizeof(sec_ws_key_field_str) - 1) == 0) {
			copy_substr(line + sizeof(sec_ws_key_field_str),
				hh->sec_websocket_key,
				sizeof(hh->sec_websocket_key), '\r');
			hh->sec_websocket_key_cnt++;
		}

		line = strtok_r(NULL, "\r\n", &saveptr);
		bytes_cnt += line ? strlen(line) : 0;
		bytes_cnt += sizeof("\r\n") - 1;
	}

	hh->final = true;
	return bytes_cnt;
}
