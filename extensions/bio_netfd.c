#include <openssl/ssl.h>
#include "st_ssl.h"
#include "st_dns.h"
#include <arpa/inet.h>

static int netfd_write(BIO *b, const char *buf, int num);
static int netfd_read(BIO *b, char *buf, int size);
static int netfd_puts(BIO *b, const char *str);
static long netfd_ctrl(BIO *b, int cmd, long num, void *ptr);
static int netfd_new(BIO *b);
static int netfd_free(BIO *b);
int BIO_netfd_should_retry(int s);

union address_u {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
};
typedef union address_u address_t;

struct netfd_state_s {
    st_netfd_t nfd;
    /* fields for BIO_TYPE_CONNECT */
    char *param_hostname;
    char *param_port;
    u_int8_t ip[4];
    u_int16_t port;
    /* field for BIO_TYPE_ACCEPT */
    char *param_addr;
    BIO *bio_chain;
};
typedef struct netfd_state_s netfd_state_t;

static BIO_METHOD methods_st = {
    BIO_TYPE_SOCKET | BIO_TYPE_CONNECT | BIO_TYPE_ACCEPT,
    "state threads netfd",
    netfd_write,
    netfd_read,
    netfd_puts,
    NULL, /* gets() */
    netfd_ctrl,
    netfd_new,
    netfd_free,
    NULL,
};

BIO_METHOD *BIO_s_netfd(void) {
    return (&methods_st);
}

BIO *BIO_new_netfd(int fd, int close_flag) {
    BIO *ret = BIO_new(BIO_s_netfd());
    if (ret == NULL) return NULL;
    BIO_set_fd(ret, fd, close_flag);
    return ret;
}

BIO *BIO_new_netfd2(st_netfd_t nfd, int close_flag) {
    BIO *ret = BIO_new(BIO_s_netfd());
    if (ret == NULL) return NULL;
    BIO_set_fp(ret, nfd, close_flag);
    return ret;
}

static int netfd_new(BIO *b) {
    b->init = 0;
    b->num = 0;
    b->ptr = calloc(1, sizeof(netfd_state_t));
    b->flags = 0;
    return 1;
}

static void _free_netfd(BIO *b) {
    if (b == NULL) return;
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    if (s == NULL) return;
    if (s->nfd) {
        if (b->shutdown) {
            st_netfd_close(s->nfd);
        } else {
            st_netfd_free(s->nfd);
        }
        s->nfd = NULL;
    }
    if (s->param_hostname != NULL)
        OPENSSL_free(s->param_hostname);
    if (s->param_port != NULL)
        OPENSSL_free(s->param_port);
    if (s->param_addr != NULL)
        OPENSSL_free(s->param_addr);

}

static int netfd_free(BIO *b) {
    if (b == NULL) return 0;
    if (b->ptr) {
        _free_netfd(b);
        free(b->ptr);
    }
    b->ptr = NULL;
    return 1;
}

static int netfd_write(BIO *b, const char *buf, int num) {
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    return st_write(s->nfd, buf, num, ST_UTIME_NO_TIMEOUT);
}

static int netfd_read(BIO *b, char *buf, int size) {
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    return st_read(s->nfd, buf, size, ST_UTIME_NO_TIMEOUT);
}

static int netfd_puts(BIO *b, const char *str) {
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    size_t n = strlen(str);
    return st_write(s->nfd, str, n, ST_UTIME_NO_TIMEOUT);
}

static int netfd_connect(BIO *b) {
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    int ret = 0;
    int status;
    struct hostent *host = NULL;

    /* TODO: fix port lookup if for example port is in param_hostname like: "google.com:http" */
    //if (!port) port = 80;
    if (BIO_get_port(s->param_port, &s->port) <= 0) {
        ret = -1;
        goto done;
    }

    /* TODO: this leaks memory right now */
    status = st_gethostbyname_r(s->param_hostname, &host);
    if (status || host == NULL) {
        ret = -1;
        goto done;
    }

#if 0
    // if not b->init then we can do all the setup here
    /* TODO: this can be moved outside the loop i think */
    int sock;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        s->status = HTTP_STREAM_SOCKET_ERROR;
        goto done;
    }

    st_netfd_t rmt_nfd;
    if ((rmt_nfd = st_netfd_open_socket(sock)) == NULL) {
        s->status = HTTP_STREAM_SOCKET_ERROR;
        goto done;
    }
#endif

    char **p = NULL;
    for (p = host->h_addr_list; *p; p++)
    {
        address_t addr;
        memset(&addr, 0, sizeof(addr));
        if (host->h_addrtype == AF_INET) {
            addr.sa_in.sin_family = host->h_addrtype;
            addr.sa_in.sin_port = htons(s->port);
            memcpy(&addr.sa_in.sin_addr, *p, host->h_length);
        } else if (addr.sa.sa_family == AF_INET6) {
            addr.sa_in6.sin6_family = host->h_addrtype;
            addr.sa_in6.sin6_port = htons(s->port);
            memcpy(&addr.sa_in6.sin6_addr, *p, host->h_length);
        }

        // TODO: add timeout support
        //if (st_connect(s->nfd, (struct sockaddr *)&addr, sizeof(addr), s->timeout) < 0) {
        if (st_connect(s->nfd, (struct sockaddr *)&addr, sizeof(addr), ST_UTIME_NO_TIMEOUT) < 0) {
            ret = -1;
            /* TODO: maybe close and free socket here? */
            continue;
        }

        /* connected */
        ret = 1;
        break;
    }

done:
    if (host) ares_free_hostent(host);
    return ret;

}

static long netfd_ctrl(BIO *b, int cmd, long num, void *ptr) {
    netfd_state_t *s = (netfd_state_t *)b->ptr;
    long ret = 1;
    int *ip;
    const char **pptr;

    switch (cmd) {
        case BIO_C_SET_FD:
            _free_netfd(b);
            b->num = *((int *)ptr);
            b->shutdown = (int)num;
            b->init = 1;
            s->nfd = st_netfd_open(b->num);
            break;
        case BIO_C_GET_FD:
            if (b->init) {
                ip = (int *)ptr;
                if (ip) *ip=b->num;
                ret = b->num;
            } else {
                ret = -1;
            }
            break;
        case BIO_C_GET_FILE_PTR:
            if (b->init) {
                *((st_netfd_t *)ptr) = s->nfd;
            } else {
                ret = -1;
            }
            break;
        case BIO_C_SET_FILE_PTR:
            _free_netfd(b);
            b->num = st_netfd_fileno(ptr);
            b->shutdown = (int)num;
            b->init = 1;
            s->nfd = ptr;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = b->shutdown;
            break;
        case BIO_CTRL_SET_CLOSE:
            b->shutdown = (int)num;
            break;
        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        case BIO_CTRL_RESET:
            /* TODO: might need to support this for connection resets */
            break;
        case BIO_C_GET_CONNECT:
            if (ptr != NULL) {
                pptr=(const char **)ptr;
                if (num == 0) {
                    *pptr = s->param_hostname;
                } else if (num == 1) {
                    *pptr = s->param_port;
                } else if (num == 2) {
                    *pptr = (char *)&(s->ip[0]);
                } else if (num == 3) {
                    *((int *)ptr) = s->port;
                }
                if ((!b->init) || (ptr == NULL))
                    *pptr = "not initialized";
                ret = 1;
            }
            break;
        case BIO_C_SET_CONNECT:
            if (ptr != NULL)
            {
                b->init=1;
                if (num == 0) {
                    if (s->param_hostname != NULL)
                        OPENSSL_free(s->param_hostname);
                    s->param_hostname=BUF_strdup(ptr);
                } else if (num == 1) {
                    if (s->param_port != NULL)
                        OPENSSL_free(s->param_port);
                    s->param_port = BUF_strdup(ptr);
                } else if (num == 2) {
                    char buf[16];
                    unsigned char *p = ptr;

                    BIO_snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                                 p[0],p[1],p[2],p[3]);
                    if (s->param_hostname != NULL)
                        OPENSSL_free(s->param_hostname);
                    s->param_hostname=BUF_strdup(buf);
                    memcpy(&(s->ip[0]), ptr, 4);
                } else if (num == 3) {
                    //char buf[DECIMAL_SIZE(int)+1];
                    char buf[32];

                    BIO_snprintf(buf, sizeof(buf), "%d", *(int *)ptr);
                    if (s->param_port != NULL)
                        OPENSSL_free(s->param_port);
                    s->param_port=BUF_strdup(buf);
                    s->port= *(int *)ptr;
                }
            }
            break;
        case BIO_C_SET_ACCEPT:
            if (ptr != NULL) {
                if (num == 0) {
                    b->init = 1;
                    if (s->param_addr != NULL)
                        OPENSSL_free(s->param_addr);
                    s->param_addr = BUF_strdup(ptr);
                } else if (num == 1) {
                    // no blocking io with state-threads
                    /*data->accept_nbio = (ptr != NULL);*/
                } else if (num == 2) {
                    if (s->bio_chain != NULL)
                        BIO_free(s->bio_chain);
                    s->bio_chain = (BIO *)ptr;
                }
            }
            break;
        case BIO_C_DO_STATE_MACHINE:
            ret = netfd_connect(b);
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}

