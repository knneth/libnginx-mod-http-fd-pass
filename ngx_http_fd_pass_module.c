/*
 * Copyright (C) Bridge Technologies Co AS
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY  199

static char *ngx_http_fd_pass_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_fd_pass_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void *ngx_http_fd_pass_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_fd_pass_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_fd_pass_commands[] = {
    { ngx_string("fd_pass"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_http_fd_pass_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};


static ngx_http_module_t  ngx_http_fd_pass_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    ngx_http_fd_pass_create_loc_conf, /* create location configuration */
    ngx_http_fd_pass_merge_loc_conf,  /* merge location configuration */
};


ngx_module_t  ngx_http_fd_pass_module = {
    NGX_MODULE_V1,
    &ngx_http_fd_pass_module_ctx,   /* module context */
    ngx_http_fd_pass_commands,      /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


/**
 * Location configuration. Shared between all requests for a specific location.
 */
typedef struct {
    ngx_addr_t  *socket_addr; /**< Backend socket address (AF_UNIX) */
} ngx_http_fd_pass_loc_conf_t;


/**
 * Request context.
 */
typedef struct {
    ngx_peer_connection_t  peer;

    /**
     * Data read from the client that we have not yet fully written to the
     * backend.
     */
    size_t                 client_buf_pos;
    size_t                 client_buf_end;
    u_char                 client_buf[4096];
} ngx_http_fd_pass_ctx_t;


/**
 * Main logic to build SCGI headers, pass the client's FD, and handle kTLS details.
 *
 * @param[in] r   The active HTTP request object
 * @param[in] ctx Pointer to our custom fd_pass context (contains peer connection, etc.)
 * @return NGX_DONE on success, NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY if partial kTLS,
 *         or standard HTTP error code on failure.
 */
static ngx_int_t
ngx_http_fd_pass_handover(ngx_http_request_t *r, ngx_http_fd_pass_ctx_t *ctx)
{
    // Sized to accomodate a variable number of semi-fixed headers together with
    // two user-provided request strings
    int            ktls_tx_only = 0;
    const size_t   server_buflen = 2048 + r->unparsed_uri.len + r->args.len;
    u_char        *server_buf = ngx_palloc(r->pool, server_buflen);
    u_char        *server_end = server_buf + server_buflen;
    u_char        *server_last = server_buf;

    if (server_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Unlike spec-compliant SCGI, we never buffer the client request body prior to
    // establishing a connection to the backend. The backend will be responsible for
    // receiving it directly. We'll still put CONTENT_LENGTH=0 into the SCGI headers
    // for compatibility with the SCGI spec.
    server_last = ngx_slprintf(server_last, server_end, "CONTENT_LENGTH%Z0%Z");
    // Spec-compliant SCGI requires "1". We will send "1+fd_pass".
    server_last = ngx_slprintf(server_last, server_end, "SCGI%Z1+fd_pass%Z");

    if (r->connection->ssl) {
        SSL *ssl = r->connection->ssl->connection;
        BIO *bio = SSL_get_wbio(r->connection->ssl->connection);
        if (BIO_get_ktls_send(bio) != 1) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Attempting to enable kTLS for HTTPS FD_PASS");
            SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
            if (!BIO_get_ktls_send(bio)) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "kTLS is required for HTTPS FD_PASS, but could not be enabled");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        const int ktls_recv = BIO_get_ktls_recv(bio);
        if (ktls_recv != 1) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "kTLS in TX direction only (OpenSSL 3.0/3.1 supports RX+TX only with TLSv1.2)");
            ktls_tx_only = 1;
        }

        server_last = ngx_slprintf(server_last, server_end, "HTTPS%Zon%Z");
        // kTLS RX unsupported on OpenSSL 3.0 with TLSv1.3. Only enabled for
        // TLSv1.2 or after upgrade to OpenSSL 3.2+.
        server_last = ngx_slprintf(server_last, server_end, "KTLS_RX%Z%d%Z", ktls_recv);
    }

    if (r->connection->addr_text.data) {
        server_last = ngx_slprintf(server_last, server_end, "REMOTE_ADDR%Z%V%Z", &r->connection->addr_text);
        server_last = ngx_slprintf(server_last, server_end, "REMOTE_PORT%Z%ui%Z", ngx_inet_get_port(r->connection->sockaddr));
    }
    server_last = ngx_slprintf(server_last, server_end, "REQUEST_METHOD%Z%V%Z", &r->main->method_name);
    server_last = ngx_slprintf(server_last, server_end, "REQUEST_URI%Z%V%Z", &r->unparsed_uri);

    u_char     addr[NGX_SOCKADDR_STRLEN];
    ngx_str_t  server_addr = {
        .len = sizeof(addr),
        .data = addr,
    };
    if (ngx_connection_local_sockaddr(r->connection, &server_addr, 0) == NGX_OK) {
        server_last = ngx_slprintf(server_last, server_end, "SERVER_ADDR%Z%V%Z", &server_addr);
        server_last = ngx_slprintf(server_last, server_end, "SERVER_PORT%Z%ui%Z", ngx_inet_get_port(r->connection->local_sockaddr));
    }
    server_last = ngx_slprintf(server_last, server_end, "QUERY_STRING%Z%V%Z", &r->args);

    if (server_last >= server_end) {
        // Headers may be mangled
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "post-condition failed at line %d", __LINE__);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Prepare headers */
    size_t            headers_size = 0;
    ngx_list_part_t  *part = NULL;

    // @TODO: Use ngx_http_link_multi_headers() to combine headers with identical
    // names as required by the SCGI specification.
    for (part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *headers = part->elts;

        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            headers_size += strlen("HTTP_") + headers[i].key.len + 1 + headers[i].value.len + 1;
        }
    }

    // Final terminator
    headers_size += 1;

    u_char  *headers_buf = ngx_palloc(r->pool, headers_size);
    if (headers_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char  *headers_end = headers_buf + headers_size;
    u_char  *headers_last = headers_buf;

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *headers = part->elts;

        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            headers_last = ngx_cpymem(headers_last, "HTTP_", strlen("HTTP_"));
            for (size_t n = 0; n < headers[i].key.len; n++) {
                u_char ch = headers[i].key.data[n];
                if (ch == '-') {
                    ch = '_';
                } else {
                    ch = ngx_toupper(ch);
                }
                *headers_last++ = ch;
            }
            *headers_last++ = '\0';
            headers_last = ngx_cpymem(headers_last, headers[i].value.data, headers[i].value.len);
            *headers_last++ = '\0';
        }
    }

    *headers_last++ = ',';

    if (headers_last != headers_end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "post-condition failed at line %d", __LINE__);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    char           scgi_header[NGX_SIZE_T_LEN + 1];
    char           control[CMSG_SPACE(sizeof(int))] = {};
    const size_t   server_len = server_last - server_buf;
    struct iovec   iov[3];
    struct msghdr  msg = {
        .msg_iov = iov,
        .msg_iovlen = 3,
        .msg_control = control,
        .msg_controllen = sizeof(control),
     };

    iov[0].iov_base = scgi_header;
    iov[0].iov_len = snprintf(scgi_header, sizeof(scgi_header), "%zu:", server_len + headers_size - 1);
    iov[1].iov_base = server_buf;
    iov[1].iov_len = server_len;
    iov[2].iov_base = headers_buf;
    iov[2].iov_len = headers_size;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    *((int *)CMSG_DATA(cmsg)) = r->connection->fd;

    // Send the HTTP request headers together with the socket file descriptor
    if (sendmsg(ctx->peer.connection->fd, &msg, MSG_NOSIGNAL) <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno, "sendmsg");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ktls_tx_only) {
        // All pool-allocated memory is freed once the request truly completes,
        // but the request could live for a long time so we'll manually free
        // buffers that are no longer needed.
        ngx_pfree(r->pool, headers_buf);
        ngx_pfree(r->pool, server_buf);
        return NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY;
    }

    return NGX_DONE;
}


/**
 * Cleanup function that closes any open backend connection and, if needed,
 * closes the client connection and frees the associated request object.
 *
 * This is typically installed as a pool cleanup handler in
 * ngx_http_fd_pass_handler().
 *
 * @param ctx The fd_pass context to clean up.
 */
static void
ngx_http_fd_pass_cleanup(ngx_http_request_t *r)
{
    ngx_http_fd_pass_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);

    if (!ctx) {
        return;
    }

    ngx_http_set_ctx(r, NULL, ngx_http_fd_pass_module);

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }
    if (r->blocked) {
        ngx_connection_t *c = r->connection;
        // See ngx_http_close_request()
        ngx_http_free_request(r, NGX_DONE);
        ngx_http_close_connection(c);
    }
}


static ngx_int_t
ngx_http_fd_pass_flush_to_backend(ngx_http_fd_pass_ctx_t *ctx)
{
    ngx_connection_t  *peer = ctx->peer.connection;
    if (peer == NULL) {
        // Not expecting to receive data unless peer was set
        return NGX_ERROR;
    }

    // While we have data left in client_buf
    while (ctx->client_buf_pos < ctx->client_buf_end) {
        ssize_t  n = peer->send(peer,
                                ctx->client_buf + ctx->client_buf_pos,
                                ctx->client_buf_end - ctx->client_buf_pos);
        if (n > 0) {
            ctx->client_buf_pos += n;
        } else {
            return n;
        }
    }

    // If we reach here, we've flushed all data in client_buf.
    return NGX_OK;
}


/**
 * Decrypts data read from the client and sends it to the backend.
 */
static ngx_int_t
ngx_http_fd_pass_relay_to_backend(ngx_http_request_t *r)
{
    ngx_int_t                rv;
    ngx_http_fd_pass_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    ngx_connection_t        *c = r->connection;

    if (c == NULL) {
        return NGX_ERROR;
    }

    // If there's pending data in client_buf, flush it first
    rv = ngx_http_fd_pass_flush_to_backend(ctx);
    if (rv != NGX_OK) {
        return rv;
    }

    // When client_buf is fully flushed, we can read more
    for ( ;; ) {
        ctx->client_buf_pos = 0;
        ctx->client_buf_end = 0;

        ssize_t  n = c->recv(c, ctx->client_buf, sizeof(ctx->client_buf));
        if (n > 0) {
            ctx->client_buf_end = n;

            rv = ngx_http_fd_pass_flush_to_backend(ctx);
            if (rv != NGX_OK) {
                // If rv == NGX_AGAIN, we still have data left. We'll flush once
                // backend is writable.
                return rv;
            }
        } else {
            return n;
        }
    }
}


/**
 * Event handler for reading from the client socket if kTLS TX-only is active.
 *
 * If the peer connection is closed or the client has shut down, triggers cleanup.
 *
 * @param ev The read event from the client connection.
 */
static void
ngx_http_fd_pass_compat_client_read_handler(ngx_event_t *rev)
{
    ngx_connection_t        *c = rev->data;
    ngx_http_request_t      *r = c->data;
    ngx_http_fd_pass_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);

    if (ngx_http_fd_pass_relay_to_backend(r) == NGX_ERROR) {
        ngx_http_fd_pass_cleanup(r);
        return;
    }

    ngx_handle_read_event(rev, 0);
    ngx_handle_write_event(ctx->peer.connection->write, 0);
}


/**
 * Minimal event handler to acknowledge that the client TX path becomes
 * writable. The client TX path is owned by the backend application.
 *
 * @param ev The write event from the client connection.
 */
static void
ngx_http_fd_pass_compat_client_write_handler(ngx_event_t *wev)
{
    ngx_handle_write_event(wev, 0);
}


/**
 * Event handler for when receive space has freed up in the backend socket.
 * Attempts to forward any buffered client data to the backend.
 *
 * @param ev The write event from the backend connection.
 */
static void
ngx_http_fd_pass_compat_peer_write_handler(ngx_event_t *wev)
{
    ngx_connection_t    *peer = wev->data;
    ngx_http_request_t  *r = peer->data;
    ngx_connection_t    *client = r->connection;

    if (ngx_http_fd_pass_relay_to_backend(r) == NGX_ERROR) {
        ngx_http_fd_pass_cleanup(r);
        return;
    }

    ngx_handle_read_event(client->read, 0);
    ngx_handle_write_event(wev, 0);
}


/**
 * Event handler for reading from the backend socket if kTLS TX-only is active.
 * Detects whether the backend has closed or sent data that must be forwarded.
 *
 * If data is received, we close the connection after relaying it to the client.
 * On EOF or error, triggers cleanup.
 *
 * @param ev The read event from the backend connection.
 */
static void
ngx_http_fd_pass_compat_peer_read_handler(ngx_event_t *rev)
{
    u_char               buf[4096];
    ssize_t              num_recv_bytes = 0;
    ssize_t              num_send_bytes = 0;
    ngx_int_t            n;
    ngx_connection_t    *peer = rev->data;
    ngx_http_request_t  *r = peer->data;
    ngx_connection_t    *c = r->connection;

    while ((n = peer->recv(peer, buf, sizeof(buf))) > 0) {
        // Backend must under normal circumstances send using the client socket
        // descriptor directly to avoid race conditions due to multiple writers.
        //
        // Still, it can be useful to relay the first data received from the
        // backend to the client for simple HTTP error responses or similar.
        // We'll do a best-effort attempt at this (relay the currently queued
        // data), then force close the connection (force eof).
        rev->eof = 1;
        num_recv_bytes += n;

        if (!c) {
            break;
        }

        ngx_int_t sent = c->send(c, buf, n);
        if (sent > 0) {
            num_send_bytes += sent;
        } else if (sent != n) {
            // Failed to relay all or some of the data
            break;
        }
    }

    if (n == NGX_ERROR || rev->eof) {
        if (num_recv_bytes) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "fd_pass: %z/%z bytes relayed from backend to client"
                          ", closing",
                          num_send_bytes, num_recv_bytes);
        }
        ngx_http_fd_pass_cleanup(r);
        return;
    }

    ngx_handle_read_event(rev, 0);
}


/**
 * The main content handler for the "fd_pass" directive.
 *
 * This function:
 *  - Validates that we are on HTTP/1.1 (FD passing doesn't work with HTTP/2).
 *  - Allocates and initializes an ngx_http_fd_pass_ctx_t for the request.
 *  - Connects to the configured UNIX socket.
 *  - Calls ngx_http_fd_pass_handover() to pass the client's FD to the backend
 *    process.
 *  - Depending on kTLS TX-only or normal operation, either:
 *     -- finalizes the request with NGX_DONE, or
 *     -- sets custom handlers to manually relay data between client and
 *        backend.
 *
 * @param[in] r The NGINX request object
 * @return NGX_DONE on success (request is taken over), or a standard HTTP
 * status code on failure.
 */
static ngx_int_t
ngx_http_fd_pass_handler(ngx_http_request_t *r)
{
    ngx_connection_t  *c = r->connection;
    if (r->http_version != NGX_HTTP_VERSION_11) {
        // The HTTP connection must be owned by the request, which isn't
        // possible with HTTP/2.0 due to muxing
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "Unsupported HTTP protocol %V (HTTP/1.1 is required)",
                      &r->http_protocol);
        return NGX_HTTP_VERSION_NOT_SUPPORTED;
    }

    ngx_http_fd_pass_loc_conf_t  *flcf = ngx_http_get_module_loc_conf(r, ngx_http_fd_pass_module);
    ngx_http_fd_pass_ctx_t       *ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "Failed to allocate context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_fd_pass_module);

    ngx_pool_cleanup_t  *cln = ngx_pool_cleanup_add(r->pool, 0);
    cln->handler = (ngx_pool_cleanup_pt)ngx_http_fd_pass_cleanup;
    cln->data = r;

    ctx->peer.sockaddr = flcf->socket_addr->sockaddr;
    ctx->peer.socklen = flcf->socket_addr->socklen;
    ctx->peer.name = &flcf->socket_addr->name;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.log = c->log;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.data = r;

    if (ngx_event_connect_peer(&ctx->peer) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Failed to connect to backend socket");
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    const ngx_int_t  rv = ngx_http_fd_pass_handover(r, ctx);
    if (rv != NGX_DONE && rv != NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Failed connection handover to backend process");
        return rv;
    }

    // Sending the socket to the backend application succeeded.
    //
    // Disabling the use of nginx's keepalive handler once request completes. Either
    // the backend process owns the receive path or we'll install custom read
    // handlers for the connection object (NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY).
    r->keepalive = 0;

    if (c->ssl) {
        // Disabling TLS close messages since the backend process owns the
        // transmission path. We must prevent nginx from sending to the client.
        SSL_set_quiet_shutdown(c->ssl->connection, 1);
    }

    if (rv == NGX_HTTP_FD_PASS_WITH_KTLS_TX_ONLY) {
        // TLS connection with kTLS receive disabled. We tell nginx to stop
        // managing the ngx_connection_t and request in the usual HTTP pipeline,
        // and take over read/write events manually.
        //
        // Nginx will no longer do standard housekeeping for the connection
        // (e.g. no keepalive, no standard timeouts, no standard read/write
        // event logic).
        //
        // - Removing the reusable flag prevents nginx from reusing the
        //   connection object.
        // - c->blocked = 1 prevents nginx from cleaning up request and
        //   connection objects on function return (see ngx_http_close_request()
        //   in nginx source code). ngx_http_fd_pass_cleanup() becomes
        //   responsible for cleaning up the HTTP connection and request
        //   objects.
        // - c->destroyed = 1 prevents nginx from interpreting c->data as a
        //   valid ngx_http_request_t pointer.
        ngx_reusable_connection(c, 0);
        r->blocked = 1;
        c->destroyed = 1;

        // Set the client connection handlers
        c->read->handler = ngx_http_fd_pass_compat_client_read_handler;
        c->write->handler = ngx_http_fd_pass_compat_client_write_handler;

        // Set the backend connection handlers
        ctx->peer.connection->data = r;
        ctx->peer.connection->read->handler =
            ngx_http_fd_pass_compat_peer_read_handler;
        ctx->peer.connection->write->handler =
            ngx_http_fd_pass_compat_peer_write_handler;
    }

    return NGX_DONE;
}


/**
 * Allocates a location configuration structure for our module.
 * Called once per location block containing "fd_pass".
 *
 * @param cf The NGINX configuration context
 * @return A pointer to the allocated structure, or NULL on failure
 */
static void *
ngx_http_fd_pass_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fd_pass_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) {
        return NULL;
    }

    return conf;
}


/**
 * Sets up the location directive "fd_pass SOCKET_PATH" in the config.
 * Performs error checking to ensure it is indeed a valid UNIX-domain socket.
 *
 * @param cf     The NGINX configuration context
 * @param cmd    The command definition (unused in this function)
 * @param conf   The module's location configuration to populate
 * @return NGX_CONF_OK on success, or an error string on failure.
 */
static char *
ngx_http_fd_pass_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                    *args = cf->args->elts;
    ngx_http_core_loc_conf_t     *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    ngx_http_fd_pass_loc_conf_t  *flcf = conf;

    if (flcf->socket_addr) {
        return "is duplicate";
    }

    ngx_url_t u = {
        .url = args[1],
        .no_resolve = 1,
    };

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        return u.err;
    }

    if (u.family != AF_UNIX || u.naddrs != 1) {
        return "is not a UNIX domain socket";
    }

    flcf->socket_addr = &u.addrs[0];
    clcf->handler = ngx_http_fd_pass_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_fd_pass_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->handler == ngx_http_fd_pass_handler) {
        // Disable lingering close for connections handled with fdpass. The
        // connection ownership is transferred to the backend process.
        clcf->lingering_close = NGX_HTTP_LINGERING_OFF;
    }

    return NGX_CONF_OK;
}
