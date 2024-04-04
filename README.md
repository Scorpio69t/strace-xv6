# XV6 Strace Implementation

This project extends the XV6 operating system by incorporating `strace`, a debugging utility that monitors and records the system calls made by a process. The implementation aims to enhance debugging capabilities, offering insights into how processes interact with the kernel.

## Team Members

- Pranav Ghildiyal
- Harshit Rajpal

## Features

- **Trace System Calls**: Enable or disable tracing on demand for individual processes.
- **Selective Tracing**: Use flags to focus on specific system calls or outcomes.
- **Child Process Tracing**: Trace system calls made by child processes.
- **Readable Output**: Enhanced output formatting for improved clarity.
- **Option Handling**: Multiple options to tailor the tracing output.
- **Output to File**: Redirect tracing output to a specified file.

## Implementation Details

We integrated `strace` within the XV6 kernel, leveraging the existing `syscall.c` structure. This involved creating user-level commands (`strace on`, `strace off`, etc.) and modifying kernel-level handling to implement filtering and output options effectively.

## Getting Started

### Building XV6 with Strace

1. Clone the XV6 repository: `git clone [repository-url] xv6`
2. Navigate to the XV6 directory: `cd xv6`
3. Build XV6 with strace support: `make`

### Using Strace

Activate strace for a process:

```bash
strace on
```

Deactivate strace:

```bash 
strace off
```

Run a command with strace enabled: 

```bash
strace run [command]
```

Dump the most recent system calls:

```bash
strace dump
```

For additional options, see the command-line help:

```bash
strace --help
```



## Installation Guide

### Prerequisites

Before installing XV6, ensure that your system meets the following requirements:

- **Git**: For repository cloning.
- **GCC**: The GNU Compiler Collection, a robust compiler for C and other languages.
- **Make**: A build automation tool that automatically builds executable programs and libraries.
- **QEMU**: An open-source machine emulator and virtualizer.

To install these prerequisites on Ubuntu, Debian, or related distributions:

```bash
sudo apt update
sudo apt install git build-essential qemu
```

For Fedora, Red Hat, or related distributions:

```bash 
sudo dnf install git gcc make qemu-system
```

### Cloning the Repository

Begin by cloning the XV6 repository into your preferred directory:

```bash

git clone https://github.com/harshitrajpal/strace-xv6
cd xv6-strace
```

## Building XV6

To compile the source code and build the XV6 operating system, run the following command:

```bash
make
```

## License

This project is open-sourced under the MIT License. The MIT License is a permissive license that is short and to the point. It lets people do anything they want with your code as long as they provide attribution back to you and don’t hold you liable.



