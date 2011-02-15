#include "st.h"
#include "st_dns.h"
#include <stdio.h>
#include <stdlib.h>

static void *do_lookup(void *arg) {

  struct hostent *host;

  int status;
  status = st_gethostbyname_r("google.com", &host);

  printf("thread: %s\n", (char *)arg);
  char **p = NULL;
  for (p = host->h_addr_list; *p; p++)
  {
    char addr_buf[46] = "??";
    inet_ntop(host->h_addrtype, *p, addr_buf, sizeof(addr_buf));
    printf("%-32s\t%s", host->h_name, addr_buf);
    puts("");
  }

  ares_free_hostent(host);

  return NULL;
}

int main(int argc, char *argv[]) {
  int status;
  st_init();
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    return 1;
  }

  st_thread_t t = st_thread_create(do_lookup, (void *)"A", 1, 1024 * 128);
  st_thread_t t2 = st_thread_create(do_lookup, (void *)"B", 1, 1024 * 128);
  st_thread_join(t, NULL);
  st_thread_join(t2, NULL);

  ares_library_cleanup();
  return 0;
}

