import re

# regular expressions
IP_REGEX = '^(0\.|10\.|127\.|169.254\.|192.0.0\.|192.0.2\.|192.88.99\.|192.168\.|198.51.100\.|203.0.113\.|255.255.255.255|198\.1[89]\.|2[23][4-9]\.|2[45][0-5]\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|100\.6[4-9]\.|100\.[789][0-9]\.|100\.1[12][0-7]\.)'
DOMAIN_REGEX = '\w+\.\w+'

# Linux system calls.
# http://man7.org/linux/man-pages/man2/syscalls.2.html
# Linux system calls categorized by linasm
# http://linasm.sourceforge.net/docs/syscalls/index.php
# Linux system calls, for 32-bit and 64-bit
# https://www.cs.utexas.edu/~bismith/test/syscalls/syscalls.html
# Generate JSON system call table from Linux source
# https://syscalls.kernelgrok.com/
FILE_SYSCALLS = {
    # File operations
    "CLOSE","CREAT","OPEN","OPENAT","NAME_TO_HANDLE_AT","OPEN_BY_HANDLE_AT","MEMFD_CREATE","MKNOD","MKNODAT","RENAME","RENAMEAT","RENAMEAT","TRUNCATE","FTRUNCATE","FALLOCATE",
    # Directory operations
    "MKDIR","MKDIRAT","RMDIR","GETCWD","CHDIR","FCHDIR","CHROOT","GETDENTS","GETDENTS64","LOOKUP_DCOOKIE",
    # Link operations
    "LINK","LINKAT","SYMLINK","SYMLINKAT","UNLINK","UNLINKAT","READLINK","READLINKAT",
    # Basic file attributes
    "UMASK","STAT","LSTAT","FSTAT","FSTATAT","CHMOD","FCHMOD","FCHMODAT","CHOWN","LCHOWN","FCHOWN","FCHOWNAT","UTIME","UTIMES","FUTIMESAT","UTIMENSAT","ACCESS","FACCESSAT",
    # Extended file attributes
    "SETXATTR","LSETXATTR","FSETXATTR","GETXATTR","LGETXATTR","FGETXATTR","LISTXATTR","LLISTXATTR","FLISTXATTR","REMOVEXATTR","LREMOVEXATTR","FREMOVEXATTR",
    # File descriptor manipulations
    "IOCTL","FCNTL","DUP","DUP2","DUP3","FLOCK",
    # Read/Write
    "READ","READV","PREAD","PREADV","WRITE","WRITEV","PWRITE","PWRITEV","LSEEK","SENDFILE",
    # Synchronized I/O
    "FDATASYNC","FSYNC","MSYNC","SYNC_FILE_RANGE","SYNC","SYNCFS",
    # Asynchronous I/O
    "IO_SETUP","IO_DESTROY","IO_SUBMIT","IO_CANCEL","IO_GETEVENTS",
    # Multiplexed I/O
    "SELECT","PSELECT6","POLL","PPOLL","EPOLL_CREATE","EPOLL_CREATE1","EPOLL_CTL","EPOLL_WAIT","EPOLL_PWAIT",
    # Monitoring file events
    "INOTIFY_INIT","INOTIFY_INIT1","INOTIFY_ADD_WATCH","INOTIFY_RM_WATCH","FANOTIFY_INIT","FANOTIFY_MARK",
    # Miscellaneous
    "FADVISE64","READAHEAD","GETRANDOM",
    # Manually added
    "_LLSEEK","STAT64","READDIR","FSTATFS64","TRUNCATE64","SENDFILE64","FSTATFS","STATFS64","CREATE_MODULE","STATFS",
    "PREADV2","FSTATAT64","FADVISE64_64","LSTAT64","FSTAT64","STATX","PWRITEV2","RENAMEAT2","FTRUNCATE64","PREAD64",
    "LCHOWN32","CHOWN32","SYNC_FILE_RANGE2","FCHOWN32","FCNTL64","PWRITE64"
}

NETWORK_SYSCALLS = {
    # Socket operations
    "SOCKET","SOCKETPAIR","SETSOCKOPT","GETSOCKOPT","GETSOCKNAME","GETPEERNAME","BIND","LISTEN","ACCEPT","ACCEPT4","CONNECT","SHUTDOWN",
    # Send/Receive
    "RECVFROM","RECVMSG","RECVMMSG","SENDTO","SENDMSG","SENDMMSG",
    # Naming
    "SETHOSTNAME","SETDOMAINNAME",
    # Packet filtering
    "BPF",
    # Manually added
    "CLOSE", "SOCKETCALL", "RECV", "SEND"
}

PROCESS_SYSCALLS = {
    # Creation and termination
    "CLONE","FORK","VFORK","EXECVE","EXECVEAT","EXIT","EXIT_GROUP","WAIT4","WAITID",
    # Pocess id
    "GETPID","GETPPID","GETTID",
    # Session id
    "SETSID","GETSID",
    # Process group id
    "SETPGID","GETPGID","GETPGRP",
    # Users and groups
    "SETUID", "GETUID","SETGID","GETGID","SETRESUID","GETRESUID","SETRESGID","GETRESGID","SETREUID","SETREGID","SETFSUID","SETFSGID","GETEUID","GETEGID","SETGROUPS","GETGROUPS",
    # Namespaces
    "SETNS",
    # Resource limits
    "SETRLIMIT","GETRLIMIT","PRLIMIT","GETRUSAGE",
    # Process scheduling
    "SCHED_SETATTR","SCHED_GETATTR","SCHED_SETSCHEDULER","SCHED_GETSCHEDULER","SCHED_SETPARAM","SCHED_GETPARAM","SCHED_SETAFFINITY","SCHED_GETAFFINITY", "SCHED_GET_PRIORITY_MAX","SCHED_GET_PRIORITY_MIN","SCHED_RR_GET_INTERVAL","SCHED_YIELD","SETPRIORITY","GETPRIORITY","IOPRIO_SET","IOPRIO_GET",
    # Virtual memory
    "BRK","MMAP","MUNMAP","MREMAP","MPROTECT","MADVISE","MLOCK","MLOCK2","MLOCKALL","MUNLOCK","MUNLOCKALL","MINCORE","MEMBARRIER","MODIFY_LDT",
    # Threads
    "CAPSET","CAPGET","SET_THREAD_AREA","GET_THREAD_AREA","SET_TID_ADDRESS","ARCH_PRCTL",
    # Miscellaneous
    "USELIB","PRCTL","SECCOMP","PTRACE","PROCESS_VM_READV","PROCESS_VM_WRITEV","KCMP","UNSHARE",
    # Manually added
    "GETUID32","SETUID32","GETEGID32","SETRESUID32","PRLIMIT64","SETREUID32","MMAP2","GETEUID32","SETFSGID32",
    "GETGROUPS32","SETGROUPS32","GETRESUID32","GETRESGID32","GETGID32","SETGID32","SETRESGID32","SETFSUID32",
    "SETREGID32","NICE",
}

TIME_SYSCALLS = {
    # Current time of day
    "TIME","SETTIMEOFDAY","GETTIMEOFDAY",
    # POSIX clocks
    "CLOCK_SETTIME","CLOCK_GETTIME","CLOCK_GETRES","CLOCK_ADJTIME","CLOCK_NANOSLEEP",
    # Clocks-based timers
    "TIMER_CREATE","TIMER_DELETE","TIMER_SETTIME","TIMER_GETTIME","TIMER_GETOVERRUN",
    # Timers
    "ALARM","SETITIMER","GETITIMER",
    # File descriptor based timers
    "TIMERFD_CREATE","TIMERFD_SETTIME","TIMERFD_GETTIME",
    # Miscellaneous
    "ADJTIMEX","NANOSLEEP","TIMES"
}

SIGNAL_SYSCALLS = {
    # Standard signals
    "KILL","TKILL","TGKILL","PAUSE",
    # Real-time signals
    "RT_SIGACTION","RT_SIGPROCMASK","RT_SIGPENDING","RT_SIGQUEUEINFO","RT_TGSIGQUEUEINFO","RT_SIGTIMEDWAIT","RT_SIGSUSPEND","RT_SIGRETURN","SIGALTSTACK",
    # File descriptor based signals
    "SIGNALFD","SIGNALFD4","EVENTFD","EVENTFD2",
    # Miscellaneous
    "RESTART_SYSCALL","SIGACTION",'SIGNAL','SIGPENDING','SIGPROCMASK','SIGRETURN','SIGSUSPEND'
}

IPC_SYSCALLS = {
    # IPC
    "IPC",
    # Pipe
    "PIPE","PIPE2","TEE","SPLICE","VMSPLICE",
    # Shared memory
    "SHMGET","SHMCTL","SHMAT","SHMDT",
    # Semaphores
    "SEMGET","SEMCTL","SEMOP","SEMTIMEDOP",
    # Futexes
    "FUTEX","SET_ROBUST_LIST","GET_ROBUST_LIST",
    # System V message queue
    "MSGGET","MSGCTL","MSGSND","MSGRCV",
    # POSIX message queue
    "MQ_OPEN","MQ_UNLINK","MQ_GETSETATTR","MQ_TIMEDSEND","MQ_TIMEDRECEIVE","MQ_NOTIFY"
}

KEY_MANAGEMENT_SYSCALLS = {
    # Linux key management system calls
    "ADD_KEY","REQUEST_KEY","KEYCTL"
}
