struct event {
  int pid;               // pid of calling process
  char command[16];      // command name
  char name[16];         // system call name
  int num;               // syscall num
  int ret;               // return value
};                       
                         
struct estats {          
  int num;               // sys call number
  int calls;             // times called
  int fails;             // num failures
};
