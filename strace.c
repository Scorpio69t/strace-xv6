#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

void dumpstrace(int);
void usage(void);
void setcstrace(char*);
void execstrace(char*,char**);
void dumpstrace(int);
void handleflags(char*,char*);


char buf[1024];
int e, s, f, o, fd, c;

int main(int argc, char *argv[]) {
  int i;
  char syscall[128], ofile[128];
  e = s = f = o = fd = c = 0;
  i = 1;

  if (argc <= 1) {
    usage();
    exit();
  }

  while (argv[i][0] == '-') {
    switch(argv[i][1]) {
      case 'e':
        e = 1;
        if (!argv[++i]) {
          printf(1, "Usage: strace -e [command name]\n");
          exit();
        } else {
          strcpy(syscall, argv[i]);
        }
        break;
      case 's':
        if (argv[i+1] && argv[i+1][0] != '-') {
          printf(1, "Usage: strace -s\n");
          exit();
        }
        s = 1;
        break;
      case 'f':
        if (argv[i+1] && argv[i+1][0] != '-') {
          printf(1, "Usage: strace -f\n");
          exit();
        }
        f = 1;
        break;
      case 'o':
        o = 1;
        if (!argv[++i]) {
          printf(1, "Usage: strace -o [filename]\n");
          exit();
        } else {
          strcpy(ofile, argv[i]);
        }
        break;
      case 'c':
        if (argv[i+1] && argv[i+1][0] != '-') {
          printf(1, "Usage: strace -c\n");
          exit();
        }
        c = 1;
        break;
    }
    i++;
  }
  if (e != 0 || s != 0 || f != 0 || o != 0 || c != 0) {
    handleflags(syscall, ofile);
    exit();
  }

  if (!strcmp(argv[1], "on") || !strcmp(argv[1], "off")) {
    setcstrace(argv[1]);
    exit();
  }

  if (!strcmp(argv[1], "run")) {
    if (argc <= 2) {
      usage();
      exit();
    }
    execstrace(argv[2], argv+2);
    exit();
  }

  if (!strcmp(argv[1], "dump")) {
    fd = 1;
    dumpstrace(fd);
    exit();
  }

  else
    usage();

  exit();
}

void usage(void) {
  int s = strace_state(-1);
  if (s == 1)
    printf(1, "strace is ON\n");
  else if (s == 0)
    printf(1, "strace is OFF\n");
  printf(1, "Usage: strace [ON/OFF]... run [COMMAND]... DUMP\n");
}

void setcstrace(char *arg) {
  if (!strcmp(arg, "on"))
    strace_state(1);
  else if (!strcmp(arg, "off"))
    strace_state(0);
}

void execstrace(char *path, char **argv) {
  int pid, c;

  c = strace_state(-1);
  if ((pid = fork()) == 0) {
    strace_state(1);
    ptrace(1);
    exec(path, argv);
    printf(2, "exec %s failed\n", path);
    exit();
  }
  wait();
  strace_state(c);
}

void dumpstrace(int fd) {
  stracedump(fd);
}

void handleflags(char *syscall, char *ofile) {
  if (s && f) {
    printf(1, "strace: -s and -f flags cannot both be set\n");
    exit();
  }
  if (e && o)
    stflags(e, syscall, sizeof(syscall), s, f, o, ofile, sizeof(ofile), c);
  else if (e)
    stflags(e, syscall, sizeof(syscall), s, f, o, "", 0, c);
  else if (o)
    stflags(e, "", 0, s, f, o, ofile, sizeof(ofile), c);
  else
    stflags(e, "", 0, s, f, o, "", 0, c);
}
