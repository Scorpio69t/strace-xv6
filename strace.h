struct event {
  int pid;               // pid of calling process
  char command[32];      // command name
  char name[32];         // system call name
  int num;               // syscall num
  int ret;               // return value
};                       

struct estats {          
  int num;               // sys call number
  int calls;             // times called
  int fails;             // num failures
};

#define MAXTRACE 20
#define NUMSYSCALLS 25
