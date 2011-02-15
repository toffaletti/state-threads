#include <openssl/bio.h>
#include "st.h"

extern BIO_METHOD *BIO_s_netfd(void);
extern BIO *BIO_new_netfd(int fd, int close_flag);
extern BIO *BIO_new_netfd2(st_netfd_t nfd, int close_flag);
