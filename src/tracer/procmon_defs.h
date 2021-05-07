/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef SYSMON_DEFS_H
#define SYSMON_DEFS_H

#include <linux/limits.h>
#include "linuxTypes.h"

#define CONFIG_FILE "sysmon_offsets.conf"

#define SYSMON_EBPF_DIR "src/tracer/procmonEBPF"
#define SYSMON_INSTALL_DIR "/opt/sysmon"

#define SYSMON_EULA_FILE "eula_accepted"
#define SYSMON_UMASK 077

// return values
#define READ_OKAY 0
#define UPDATE_OKAY 0

#define CMDLINE_MAX_LEN 16384 // must be power of 2
#define MAX_FDS 65535
#define LINUX_MAX_EVENT_SIZE (65536 - 24)

// tunable parameters for building paths through iteration.
// for SUB4096 it's about instruction count <4096
// for NOLOOPS it's about instruction count <32768(ish - due to signed 16bit jumps)
// for others it's about verification complexity <1M instructions
// 
// when adding code, change these to keep within these limits
#ifdef SUB4096
#define FILEPATH_NUMDIRS 6
#else
#ifdef NOLOOPS
#define FILEPATH_NUMDIRS 15
#else
#define FILEPATH_NUMDIRS 95
#endif
#endif

#define ABSOLUTE_PATH 'A'
#define RELATIVE_PATH 'R'
#define CWD_REL_PATH 'C'
#define UNKNOWN_PATH 'U'

#define NUM_REDIRECTS 4
#define DEREF_END -1


#define SYSCALL_MAX 335
#define SYSCALL_NAME_LEN 64
#define SYSCALL_ARRAY_SIZE 512

#define NUM_ARGS 6
#define ARG_ARRAY_SIZE 8
#define ARG_MASK 7

#define ACTIVE_MASK 0x1f
#define ACTIVE_SYSCALL 0x20
#define ACTIVE_NOFAIL  0x40
#define ACTIVE_PARSEV  0x80

// Event arguments structure
typedef struct a_rec {
    unsigned long      syscall_id;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
    unsigned long      return_code;
} args_s;

// configuration
typedef struct conf {
    unsigned int       userland_pid;
    //bool               events[EVENT_COUNT]; // which Sysmon events are active
    bool               active[SYSCALL_ARRAY_SIZE]; // which syscalls are active
    uint64_t           bootNsSinceEpoch;
    unsigned int       timesec[NUM_REDIRECTS];
    unsigned int       timensec[NUM_REDIRECTS];
    unsigned int       serial[NUM_REDIRECTS];
    unsigned int       arch[NUM_REDIRECTS];
    unsigned int       arg0[NUM_REDIRECTS];
    unsigned int       arg1[NUM_REDIRECTS];
    unsigned int       arg2[NUM_REDIRECTS];
    unsigned int       arg3[NUM_REDIRECTS];
    unsigned int       parent[NUM_REDIRECTS];
    unsigned int       pid[NUM_REDIRECTS];
    unsigned int       ppid[NUM_REDIRECTS];
    unsigned int       auid[NUM_REDIRECTS];
    unsigned int       cred[NUM_REDIRECTS];
    unsigned int       cred_uid[NUM_REDIRECTS];
    unsigned int       cred_gid[NUM_REDIRECTS];
    unsigned int       cred_euid[NUM_REDIRECTS];
    unsigned int       cred_suid[NUM_REDIRECTS];
    unsigned int       cred_fsuid[NUM_REDIRECTS];
    unsigned int       cred_egid[NUM_REDIRECTS];
    unsigned int       cred_sgid[NUM_REDIRECTS];
    unsigned int       cred_fsgid[NUM_REDIRECTS];
    unsigned int       ses[NUM_REDIRECTS];
    unsigned int       start_time[NUM_REDIRECTS];
    unsigned int       tty[NUM_REDIRECTS];
    unsigned int       comm[NUM_REDIRECTS];
    unsigned int       exe_path[NUM_REDIRECTS];
    unsigned int       mm_arg_start[NUM_REDIRECTS];
    unsigned int       mm_arg_end[NUM_REDIRECTS];
    unsigned int       mm_start_code[NUM_REDIRECTS];
    unsigned int       mm_end_code[NUM_REDIRECTS];
    unsigned int       pwd_path[NUM_REDIRECTS];
    unsigned int       path_vfsmount[NUM_REDIRECTS];
    unsigned int       path_dentry[NUM_REDIRECTS];
    unsigned int       dentry_parent[NUM_REDIRECTS];
    unsigned int       dentry_name[NUM_REDIRECTS];
    unsigned int       dentry_inode[NUM_REDIRECTS];
    unsigned int       inode_mode[NUM_REDIRECTS];
    unsigned int       inode_ouid[NUM_REDIRECTS];
    unsigned int       inode_ogid[NUM_REDIRECTS];
    unsigned int       mount_mnt[NUM_REDIRECTS];
    unsigned int       mount_parent[NUM_REDIRECTS];
    unsigned int       mount_mountpoint[NUM_REDIRECTS];
    unsigned int       max_fds[NUM_REDIRECTS];
    unsigned int       fd_table[NUM_REDIRECTS];
    unsigned int       fd_path[NUM_REDIRECTS];
} config_s;


#endif
