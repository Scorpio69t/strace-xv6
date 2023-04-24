#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "syscall.h"
#include "strace.h"
#include "format.c"
#include "fs.h"
#include "fcntl.h"


// User code makes a system call with INT T_SYSCALL.
// System call number in %eax.
// Arguments on the stack, from the user call to the C
// library system call function. The saved user %esp points
// to a saved program counter, and then the first argument.

// Fetch the int at addr from the current process.
int
fetchint(uint addr, int *ip)
{
  if(addr >= proc->sz || addr+4 > proc->sz)
    return -1;
  *ip = *(int*)(addr);
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Doesn't actually copy the string - just sets *pp to point at it.
// Returns length of string, not including nul.
int
fetchstr(uint addr, char **pp)
{
  char *s, *ep;

  if(addr >= proc->sz)
    return -1;
  *pp = (char*)addr;
  ep = (char*)proc->sz;
  for(s = *pp; s < ep; s++)
    if(*s == 0)
      return s - *pp;
  return -1;
}

// Fetch the nth 32-bit system call argument.
int
argint(int n, int *ip)
{
  return fetchint(proc->tf->esp + 4 + 4*n, ip);
}

// Fetch the nth word-sized system call argument as a pointer
// to a block of memory of size bytes.  Check that the pointer
// lies within the process address space.
int
argptr(int n, char **pp, int size)
{
  int i;

  if(argint(n, &i) < 0)
    return -1;
  if(size < 0 || (uint)i >= proc->sz || (uint)i+size > proc->sz)
    return -1;
  *pp = (char*)i;
  return 0;
}

// Fetch the nth word-sized system call argument as a string pointer.
// Check that the pointer is valid and the string is nul-terminated.
// (There is no shared writable memory, so the string can't change
// between this check and being used by the kernel.)
int
argstr(int n, char **pp)
{
  int addr;
  if(argint(n, &addr) < 0)
    return -1;
  return fetchstr(addr, pp);
}

extern int sys_chdir(void);
extern int sys_close(void);
extern int sys_dup(void);
extern int sys_exec(void);
extern int sys_exit(void);
extern int sys_fork(void);
extern int sys_fstat(void);
extern int sys_getpid(void);
extern int sys_kill(void);
extern int sys_link(void);
extern int sys_mkdir(void);
extern int sys_mknod(void);
extern int sys_open(void);
extern int sys_pipe(void);
extern int sys_read(void);
extern int sys_sbrk(void);
extern int sys_sleep(void);
extern int sys_unlink(void);
extern int sys_wait(void);
extern int sys_write(void);
extern int sys_uptime(void);
extern int sys_cstrace(void);
extern int sys_pstrace(void);
extern int sys_stracedump(void);
extern int sys_cstflags(void);

static int (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_cstrace] sys_cstrace, 
[SYS_pstrace] sys_pstrace, 
[SYS_stracedump] sys_stracedump,
[SYS_cstflags] sys_cstflags,
};

void syscall(void) {
  int num, ex, ret, nowrite;
  struct event *e;

  ex = 0;
  nowrite = 0;
  num = proc->tf->eax;
  if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {

    /*
    * Begin strace handler
    */
    if (proc->pstrace == 1) {
      if (cst() == 1 && num == SYS_write) {
        nowrite = 1;
        ret = 1;
      }

      if (cste())
        if (strncmp(cstename(), getname(num), strlen(cstename()))) {
          if (num == SYS_exit) {
            if (cstc())
              dumpstats();
            resetcflags();
          }
          goto end_strace_handler;
        }

      if (num == SYS_exec || num == SYS_exit) {
        if (cstf()) {
          if (num == SYS_exit) {
            if (cstc()) {
              dumpstats();
              statsinit();
            }
            resetcflags();
          }
          goto end_strace_handler;
        }
        e = rbappend(proc, num);
        if (cst() == 1 && cstc() == 0)
          writetrace(e);
        if (num == SYS_exit) {
          if (cstc()) {
            updatestats(e);
            dumpstats();
            statsinit();
          }
          resetcflags();
        }
        e->ret = 1;
        if (cstc())
          updatestats(e);
        proc->tf->eax = syscalls[num]();
        e->ret = proc->tf->eax;
        if (e->ret == -1 && cstc())
          updatestats(e);
      } else {
        if (!nowrite) {
          proc->tf->eax = syscalls[num]();
          ex = 1;
          ret = proc->tf->eax;
        }
        if (csts() && ret == -1)
          goto end_strace_handler;
        if (cstf() && ret != -1)
          goto end_strace_handler;
        e = rbappend(proc, num);
        e->ret = ret;
        if (cst() == 1 && !cstc())
          writetrace(e);
        if (cstc())
          updatestats(e);
      }
    }
    /*
    * End strace handler
    */

    else {
    end_strace_handler:
      if (!ex && !nowrite)
        proc->tf->eax = syscalls[num]();
    }
  } else {
    cprintf("%d %s: unknown sys call %d\n", proc->pid, proc->name, num);
    proc->tf->eax = -1;
  }
}
#define MAXTRACE 20
#define NUMSYSCALLS 25

struct event rbuf[MAXTRACE];
struct estats stats[NUMSYSCALLS];

void writetrace(struct event *e) {
  cprintf("TRACE: pid = %d | command name = %s | syscall = %s", e->pid, e->command, e->name);
  if (e->num != SYS_exec && e->num != SYS_exit)
    cprintf(" | return value = %d", e->ret);
  cprintf("\n");
}

char* getname(int num) {
  switch (num) {
    case SYS_fork: return "fork";
    case SYS_exit: return "exit";
    case SYS_wait: return "wait";
    case SYS_pipe: return "pipe";
    case SYS_read: return "read";
    case SYS_kill: return "kill";
    case SYS_exec: return "exec";
    case SYS_fstat: return "fstat";
    case SYS_chdir: return "chdir";
    case SYS_dup: return "dup";
    case SYS_getpid: return "getpid";
    case SYS_sbrk: return "sbrk";
    case SYS_sleep: return "sleep";
    case SYS_uptime: return "uptime";
    case SYS_open: return "open";
    case SYS_write: return "write";
    case SYS_mknod: return "mknod";
    case SYS_unlink: return "unlink";
    case SYS_link: return "link";
    case SYS_mkdir: return "mkdir";
    case SYS_close: return "close";
    case SYS_cstrace: return "cstrace";
    case SYS_pstrace: return "pstrace";
    case SYS_stracedump: return "stracedump";
    case SYS_cstflags: return "cstflags";
  }
  return "";
}

/*
* Ring Buffer Functions
*/

void rbprint() {
  int i;
  struct event *e;
   
  i = 0;
  for (e = rbuf; e < &rbuf[MAXTRACE]; e++) {
    cprintf("RBENTRY %d: pid = %d | command = %s | name = %s", i, e->pid, e->command, e->name);
    if (e->num != SYS_exec && e->num != SYS_exit)
      cprintf(" | return value = %d", e->ret);
    cprintf("\n");
    i++;
  }
}

void rbinit() {
  struct event *e;

  for (e = rbuf; e < &rbuf[MAXTRACE]; e++) {
    e->pid = -1;
    safestrcpy(e->command, """", sizeof(e->command));
    safestrcpy(e->name, """", sizeof(e->name));
    e->num = 0;
    e->ret = 0;
  }
}

void rbpop() {
  struct event *e, *next;
  int i = 0;

  for (e = rbuf; e < &rbuf[MAXTRACE]; e++) {
    next = e+1;
    e->pid = next->pid;
    safestrcpy(e->command, next->command, sizeof(e->command));
    safestrcpy(e->name, next->name, sizeof(e->name));
    e->num = next->num;
    e->ret = next->ret;
    i++;
    if (i == MAXTRACE-1) {
      next->pid = -1;
      safestrcpy(next->command, """", sizeof(next->command));
      safestrcpy(next->name, """", sizeof(next->name));
      next->num = 0;
      next->ret = 0;
      break;
    }
  }
}

struct event *rbappend(struct proc *p, int num) {
  struct event *e;

  // Look for an open spot
  for (e = rbuf; e < &rbuf[MAXTRACE]; e++)
    if (e->pid == -1)
      goto add;
  
  // Buffer is full
  rbpop();
  e = &rbuf[MAXTRACE-1];

add:
  e->pid = p->pid;
  safestrcpy(e->command, p->name, sizeof(e->command));
  safestrcpy(e->name, getname(num), sizeof(e->name));
  e->num = num;
  e->ret = 0;
  return e;
}

int rbdump(struct file *f) {
  struct event *e;
  char chrpid[32];
  char chrret[32];
  
  for (e = rbuf; e < &rbuf[MAXTRACE]; e++) {
    if (e->pid == -1)
      break;
    filewrite(f, "TRACE: pid = \0", strlen("TRACE: pid = \0"));
    integer_to_string(chrpid, 32, e->pid);
    filewrite(f, chrpid, strlen(chrpid));
    filewrite(f, " | command name = ", strlen(" | command name = "));
    filewrite(f, e->command, strlen(e->command));
    filewrite(f, " | syscall = ", strlen(" | syscall = "));
    filewrite(f, e->name, strlen(e->name));
    if (e->num != SYS_exec && e->num != SYS_exit) {
      filewrite(f, " | return value = ", strlen(" | return value = "));
      integer_to_string(chrret, 32, e->num);
      filewrite(f, chrret, strlen(chrret));
    }
    filewrite(f, "\n", strlen("\n"));
  }
  
  return 1;
}

void statsinit(void) {
  int i;
  struct estats *e;

  i = 0;
  for (e = stats; e < &stats[NUMSYSCALLS]; e++) {
    e->num = ++i;
    e->calls = 0;
    e->fails = 0;
  }
}

void updatestats(struct event *e) {
  struct estats *es;

  es = stats+(e->num-1);
  if (e->num == SYS_exec && e->ret == -1) {
    es->fails++;
  } else {
    es->calls++;
    if (e->ret == -1)
      es->fails++;
  }
}

static int padname(char *name) {
  return 13-strlen(name);
}

static int numdigits(int n) {
  int count = 0;  
  while(n!=0) {  
    n=n/10;  
    count++;  
  }
  return count;
}

static int padcalls(int calls) {
  return 7-numdigits(calls);
}

void dumpstats(void) {
  struct estats *es;
  int i;

  if (cst() == 0) {
    cprintf("strace is OFF\n");
    exit();
  }

  // Print Stats
  cprintf("\n syscall      calls  errors     \n");
  cprintf(" -----------  -----  -------\n");
  for (es = stats; es < &stats[NUMSYSCALLS]; es++) {
    if (es->calls > 0) {
      cprintf(" %s", getname(es->num));
      for (i = 0; i < padname(getname(es->num)); i++)
        cprintf(" ");
      cprintf("%d", es->calls);
      for (i = 0; i < padcalls(es->calls); i++)
        cprintf(" ");
      cprintf("%d", es->fails);
      cprintf("\n");
    }
  }
  cprintf("\n");
}

