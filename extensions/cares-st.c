#include "st.h"
#include "st_dns.h"
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SEC2USEC(s) ((s)*1000000LL)

static __thread int _need_init = 1;
static __thread ares_channel _channel;

/* TODO: use getaddrinfo/getnameinfo style api. this will avoid memory leaks */

/* deep copy hostent struct. memory allocation scheme
 * borrowed from ares_free_hostent.
 */
static void copy_hostent(struct hostent *from, struct hostent **to) {
  *to = calloc(1, sizeof(struct hostent));
  (*to)->h_name = strdup(from->h_name);
  int n = 0;
  while (from->h_aliases && from->h_aliases[n]) {
    n++;
  }
  (*to)->h_aliases = calloc(n+1, sizeof(char *));
  while (n) {
    if (from->h_aliases[n]) {
      (*to)->h_aliases[n] = strdup(from->h_aliases[n]);
    }
    n--;
  }
  (*to)->h_addrtype = from->h_addrtype;
  n = 0;
  while (from->h_addr_list && from->h_addr_list[n]) {
    n++;
  }
  (*to)->h_length = from->h_length;
  (*to)->h_addr_list = calloc(n+1, sizeof(char *));
  (*to)->h_addr_list[0] = calloc(n, from->h_length);
  if (n)
    memcpy((*to)->h_addr_list[0], from->h_addr_list[0], n*from->h_length);
  while (n > 1) {
    n--;
    (*to)->h_addr_list[n] = (*to)->h_addr_list[0] + (n * from->h_length);
  }
}

/* convert read and write fd_set to pollfd
 * max_fd pollfds will be malloced and returned in fds_p
 * actual number of fds will be returned in nfds;
 */
static void fd_sets_to_pollfd(fd_set *read_fds, fd_set *write_fds, int max_fd, struct pollfd **fds_p, int *nfds) {
  /* using max_fd is over allocating */
  struct pollfd *fds = calloc(max_fd, sizeof(struct pollfd));
  int ifd = 0;
  for (int fd = 0; fd<max_fd; fd++) {
    fds[ifd].fd = fd;
    if (FD_ISSET(fd, read_fds)) {
      fds[ifd].events |= POLLIN;
    }
    if (FD_ISSET(fd, write_fds)) {
      fds[ifd].events |= POLLOUT;
    }
    /* only increment the fd index if it exists in the fd sets */
    if (fds[ifd].events != 0) {
      ifd++;
    }
  }
  *fds_p = fds;
  *nfds = ifd;
}

/* convert pollfd to read and write fd_sets */
static void pollfd_to_fd_sets(struct pollfd *fds, int nfds, fd_set *read_fds, fd_set *write_fds) {
  FD_ZERO(read_fds);
  FD_ZERO(write_fds);
  for (int i = 0; i<nfds; i++) {
    if (fds[i].revents & POLLIN) {
      FD_SET(fds[i].fd, read_fds);
    }
    if (fds[i].revents & POLLOUT) {
      FD_SET(fds[i].fd, write_fds);
    }
  }
}

static void gethostbyname_callback(void *arg, int status, int timeouts, struct hostent *host) {
  struct hostent **_host = (struct hostent **)arg;
  (void)timeouts; /* the number of times the quest timed out during request */
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ARES: %s\n", ares_strerror(status));
    return;
  }

  copy_hostent(host, _host);
}

int st_gethostbyname_r(const char *name, struct hostent **host) {
  *host = NULL;
  if (_need_init) {
    int status = ares_init(&_channel);
    if (status != ARES_SUCCESS) {
      ares_destroy(_channel);
      return status;
    }
    _need_init = 0;
  }

  ares_gethostbyname(_channel, name, AF_INET, gethostbyname_callback, host);

  fd_set read_fds, write_fds;
  struct timeval *tvp, tv;
  int max_fd, nfds;
  for (;;)
  {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    max_fd = ares_fds(_channel, &read_fds, &write_fds);
    if (max_fd == 0)
      break;

    struct pollfd *fds;
    fd_sets_to_pollfd(&read_fds, &write_fds, max_fd, &fds, &nfds);
    tvp = ares_timeout(_channel, NULL, &tv);
    /*select(nfds, &read_fds, &write_fds, NULL, tvp); */
    /* TODO: get timeout working */
    if (st_poll(fds, nfds, SEC2USEC(tvp->tv_sec)+tvp->tv_usec) == -1) {
      /* TODO: handle errors here */
    }
    pollfd_to_fd_sets(fds, nfds, &read_fds, &write_fds);
    free(fds);
    ares_process(_channel, &read_fds, &write_fds);
  }
  return ARES_SUCCESS;
}
