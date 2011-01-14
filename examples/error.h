#ifndef ERROR_H
#define ERROR_H 1

extern void err_sys_report(int fd, const char *fmt, ...);
extern void err_sys_quit(int fd, const char *fmt, ...);
extern void err_sys_dump(int fd, const char *fmt, ...);
extern void err_report(int fd, const char *fmt, ...);
extern void err_quit(int fd, const char *fmt, ...);

#endif
