
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>

#include <sys/types.h>
#include <linux/netfilter_ipv4.h>

typedef struct {
    ngx_tcp_session_t  *s;
    struct sockaddr_in  sockaddr;
    socklen_t           socklen;
    ngx_int_t           tries;
} ngx_tcp_upstream_transparent_peer_data_t;

static ngx_int_t ngx_tcp_upstream_init_transparent_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us);
static ngx_int_t ngx_tcp_upstream_get_transparent_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_tcp_upstream_transparent(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_tcp_upstream_transparent_commands[] = {

    { ngx_string("transparent"),
      NGX_TCP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_tcp_upstream_transparent,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_transparent_module_ctx = {
    NULL,                                 

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
};

ngx_module_t  ngx_tcp_upstream_transparent_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_transparent_module_ctx, /* module context */
    ngx_tcp_upstream_transparent_commands,    /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_tcp_upstream_init_transparent(ngx_conf_t *cf, ngx_tcp_upstream_srv_conf_t *us)
{
    us->peer.init = ngx_tcp_upstream_init_transparent_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_init_transparent_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_tcp_upstream_transparent_peer_data_t  *tp;

    tp = ngx_palloc(s->pool, sizeof(ngx_tcp_upstream_transparent_peer_data_t));
    if (tp == NULL) {
        return NGX_ERROR;
    }

    tp->tries = 0;
    tp->socklen = sizeof(tp->sockaddr);
    tp->s = s;

    s->upstream->peer.data = tp;

    s->upstream->peer.get = ngx_tcp_upstream_get_transparent_peer;
    s->upstream->peer.free = ngx_tcp_upstream_free_round_robin_peer;
    s->upstream->peer.tries = 1;
    s->upstream->peer.check_index = NGX_INVALID_CHECK_INDEX;
    s->upstream->peer.name = NULL;
#if (NGX_TCP_SSL)
    s->upstream->peer.set_session =
                               ngx_tcp_upstream_set_round_robin_peer_session;
    s->upstream->peer.save_session =
                               ngx_tcp_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_get_transparent_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_transparent_peer_data_t  *tp = data;

    char                str[INET_ADDRSTRLEN];
    size_t              len;
    ngx_str_t          *name;

    getsockopt(tp->s->connection->fd, SOL_IP, SO_ORIGINAL_DST, &tp->sockaddr, &tp->socklen);

    len = NGX_INET_ADDRSTRLEN + sizeof(":65536") - 1;

    name = ngx_pnalloc(tp->s->pool, sizeof(ngx_str_t));
    if (name == NULL) {
        return NGX_ERROR;
    }
    name->data = ngx_pnalloc(tp->s->pool, len);
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    len = ngx_inet_ntop(AF_INET, &tp->sockaddr.sin_addr, name->data, NGX_INET_ADDRSTRLEN);
    len = ngx_sprintf(name->data + len, ":%d", ntohs(tp->sockaddr.sin_port)) - name->data;

    name->len = len;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "get transparent peer: %V", name);

    pc->cached = 0;
    pc->connection = NULL;

    pc->sockaddr = (struct sockaddr *) (&tp->sockaddr);
    pc->socklen = tp->socklen;
    pc->name = name;

    return NGX_OK;
}


static char *
ngx_tcp_upstream_transparent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_upstream_srv_conf_t  *uscf;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);

    uscf->peer.init_upstream = ngx_tcp_upstream_init_transparent;

    /* transparent upstream don't need server, we create one manually. */
    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    uscf->flags = NGX_TCP_UPSTREAM_CREATE
                  |NGX_TCP_UPSTREAM_MAX_FAILS
                  |NGX_TCP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_TCP_UPSTREAM_MAX_BUSY
                  |NGX_TCP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}
