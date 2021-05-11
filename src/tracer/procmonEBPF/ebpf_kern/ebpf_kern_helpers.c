/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#ifndef KERN_HELPERS_H
#define KERN_HELPERS_H

#include "ebpf_kern_common.h"

// Our own inline helper functions

// return pointer to struct member
__attribute__((always_inline))
static inline void *deref_member(void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    void *result = ref;
    unsigned int breakindex = NUM_REDIRECTS - 1;
    bool breakloop = false; // problems with clang loop unrolling led to this...

    if (!refs || refs[0] == DEREF_END)
        return NULL;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<NUM_REDIRECTS - 1; i++) {
        if (!breakloop) {
            if (refs[i+1] == DEREF_END) {
                breakindex = i;
                breakloop = true;
            } else {
                if (bpf_probe_read(&result, sizeof(result), ref + refs[i]) != READ_OKAY)
                    return NULL;
                ref = result;
                if (!ref)
                    return NULL;
            }
        }
    }

    return result + refs[breakindex & (NUM_REDIRECTS - 1)];
}

// return value pointed to by struct member
__attribute__((always_inline))
static inline uint64_t deref_ptr(void *base, unsigned int *refs)
{
    uint64_t result = 0;
    void *ref;

    ref = deref_member(base, refs);

    if (bpf_probe_read(&result, sizeof(result), ref) != READ_OKAY)
        return 0;

    return result;
}

// extract string from struct
__attribute__((always_inline))
static inline bool deref_string_into(char *dest, unsigned int size, void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    uint64_t result = 0;

    ref = deref_member(base, refs);

    if (ref && bpf_probe_read_str(dest, size, ref) > 0)
        return true;
    else {
        *dest = 0x00;
        return false;
    }
}

// extract filepath from dentry
__attribute__((always_inline))
static inline uint32_t deref_filepath_into(char *dest, void *base, unsigned int *refs, config_s *config)
{
    int dlen, dlen2;
    char *dname = NULL;
    char *temp = NULL;
    unsigned int i;
    unsigned int size = 0;
    uint32_t map_id = bpf_get_smp_processor_id();
    void *path = NULL;
    void *dentry = NULL;
    void *newdentry = NULL;
    void *vfsmount = NULL;
    void *mnt = NULL;

    // nullify string in case of error
    dest[0] = 0x00;

    path = deref_member(base, refs);
    if (!path)
        return 0;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->path_dentry[0]) != READ_OKAY)
        return 0;

    if (!dentry)
        return 0;

    // get a pointer to the vfsmount
    if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->path_vfsmount[0]) != READ_OKAY)
        return 0;

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&temppath_array, &map_id);
    if (!temp)
        return 0;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<FILEPATH_NUMDIRS; i++) {
        if (bpf_probe_read(&dname, sizeof(dname), dentry + config->dentry_name[0]) != READ_OKAY)
            return 0;
        if (!dname)
            return 0;
        // store this dentry name in start of second half of our temporary storage
        dlen = bpf_probe_read_str(&temp[PATH_MAX], PATH_MAX, dname);
        // get parent dentry
        bpf_probe_read(&newdentry, sizeof(newdentry), dentry + config->dentry_parent[0]);
        // copy the temporary copy to the first half of our temporary storage, building it backwards from the middle of it
        dlen2 = bpf_probe_read_str(&temp[(PATH_MAX - size - dlen) & (PATH_MAX - 1)], dlen & (PATH_MAX - 1), &temp[PATH_MAX]);
        // check if current dentry name is valid
        if (dlen2 <= 0 || dlen <= 0 || dlen >= PATH_MAX || size + dlen > PATH_MAX)
            return 0;
        if (size > 0)
            // overwrite the null char with a slash
            temp[(PATH_MAX - size - 1) & (PATH_MAX - 1)] = '/';
        size = (size + dlen2) & (PATH_MAX - 1);  // by restricting size to PATH_MAX we help the verifier keep the complexity
                                                // low enough so that it can analyse the loop without hitting the 1M ceiling
        // check if this is the root of the filesystem
        if (!newdentry || dentry == newdentry) {
            // check if we're on a mounted partition
            // find mount struct from vfsmount
            mnt = vfsmount - config->mount_mnt[0];
            void *parent = (void *)deref_ptr(mnt, config->mount_parent);
            // check if we're at the real root
            if (parent == mnt)
                break;
            // move to mount point
            vfsmount = parent + config->mount_mnt[0];
            newdentry = (void *)deref_ptr(mnt, config->mount_mountpoint);
            // another check for real root
            if (dentry == newdentry)
                break;
            size = (size - dlen2) & (PATH_MAX - 1);  // ditto above message about restricting size to PATH_MAX
        }

        // go up one directory
        dentry = newdentry;
    }

    // copy the path from the temporary location to the destination
    if (size == 2)
        // path is simply "/"
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[(PATH_MAX - size) & (PATH_MAX -1)]);
    else if (size > 2)
        // otherwise don't copy the extra slash
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[(PATH_MAX - (size - 1)) & (PATH_MAX -1)]);
    if (dlen <= 0)
        return 0;

    return dlen;
}

// copy commandline from task
__attribute__((always_inline))
static inline uint32_t copy_commandline(char *e, void *task, config_s *config)
{
    // read the more reliable cmdline from task_struct->mm->arg_start
    uint64_t arg_start = deref_ptr(task, config->mm_arg_start);
    uint64_t arg_end = deref_ptr(task, config->mm_arg_end);

    if (arg_start >= arg_end)
        return 0;
    int arg_len = arg_end - arg_start;
    if (arg_len > (CMDLINE_MAX_LEN - 1))
        arg_len = CMDLINE_MAX_LEN - 1;

    arg_len = arg_len & (CMDLINE_MAX_LEN - 1);
    if (bpf_probe_read(e, arg_len, (void *)arg_start) != READ_OKAY)
        return 0;

    // add nul terminator just in case
    e[arg_len] = 0x00;
    return arg_len;
}

// extract pathname from a file descriptor
__attribute__((always_inline))
static inline uint32_t fd_to_path(char *fd_path, int fd, void *task, config_s *config)
{
    int byte_count;

    // check if fd is valid
    int max_fds = deref_ptr(task, config->max_fds);
    if (fd < 0 || fd > MAX_FDS || max_fds <= 0 || fd > max_fds) {
        return 0;
    }

    // resolve the fd to the fd_path
    void **fd_table = (void **)deref_ptr(task, config->fd_table);
    if (!fd_table) {
        return 0;
    }

    void *file = NULL;
    if (bpf_probe_read(&file, sizeof(file), &fd_table[fd & MAX_FDS]) != READ_OKAY || !file) {
        return 0;
    } else {
        return deref_filepath_into(fd_path, file, config->fd_path, config);
    }
}

// wrapper for fd_to_path()
__attribute__((always_inline))
static inline uint32_t resolve_fd_path(char *pathname, int fd, void *task, config_s *config)
{
    pathname[0] = 0x00;

    if (fd > 0)
        return fd_to_path(pathname, fd, task, config);

    return 0;
}

// extract dfd pathname followed by dfd pathname, separated by null, and return total size including null
__attribute__((always_inline))
static inline uint32_t resolve_dfd_path(char *dfd_path, int dfd, char *pathname, void *task, config_s *config)
{
    int byte_count;
    int dfd_count;

    if (pathname) {
        if (bpf_probe_read(dfd_path, 1, (void *)pathname) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx)\n", pathname);
            return 0;
        }

        if (dfd_path[0] == '/') { // absolute path
            if ((byte_count = bpf_probe_read_str(dfd_path, sizeof(dfd_path),
                    (void *)pathname)) < 0) {
                BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byte_count);
                dfd_path[0] = 0x00;
                return 0;
            }
            return byte_count;
        }
    }
    if (dfd == AT_FDCWD) { // relative to current working directory
        dfd_path[0] = 'C';
        dfd_path[1] = 0x00;
        if (pathname) {
            if ((byte_count = bpf_probe_read_str(dfd_path + 2, sizeof(dfd_path) - 2,
                    (void *)pathname)) < 0) {
                BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byte_count);
                return 0;
            }
            return byte_count + 2;
        } else {
            return 2;
        }
    }
    // relative to FD
    dfd_path[0] = 'U';
    dfd_path[1] = 0x00;
    dfd_count = 2;
#ifndef SUB4096
    if ((dfd_count = fd_to_path(dfd_path, dfd, task, config)) == 0) {
        dfd_path[0] = 'U';
        dfd_path[1] = 0x00;
        dfd_count = 2;
    }
#endif
    if (pathname) {
        if ((byte_count = bpf_probe_read_str(dfd_path + dfd_count, sizeof(dfd_path) - dfd_count,
                (void *)pathname)) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byte_count);
            return 0;
        }
        return byte_count + dfd_count;
    } else {
        return dfd_count;
    }
}

// set the initial values for the event arguments
__attribute__((always_inline))
static inline void init_args(args_s *event_args, unsigned long syscall_id)
{
    memset(event_args, 0, sizeof(args_s));
    event_args->syscall_id = syscall_id;
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (unsigned int i=0; i<ARG_ARRAY_SIZE; i++) {
        event_args->a[i] = 0;
    }
}

// check if this is an event to process
__attribute__((always_inline))
static inline bool sys_enter_check_and_init(args_s *event_args, config_s *config, uint32_t syscall, uint64_t pid_tid, uint32_t cpu_id)
{
    uint32_t userland_pid = 0;
    char syscall_flags = 0;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == config->userland_pid)
        return false;

    // initialise the args
    init_args(event_args, syscall);

    return true;
}

// complete and store event
__attribute__((always_inline))
static inline void sys_enter_complete_and_store(args_s *event_args, uint32_t syscall, uint64_t pid_tid)
{
    args_s args;
    memset(&args, 0, sizeof(args_s));
    // store args in the hash
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (int i=0; i<NUM_ARGS; i++) {
        args.a[i] = event_args->a[i];
    }
    args.syscall_id = event_args->syscall_id;
    long ret = 0;
    if ((ret = bpf_map_update_elem(&args_hash, &pid_tid, &args, BPF_ANY)) != UPDATE_OKAY) {
        BPF_PRINTK("ERROR, HASHMAP: failed to update args map, %ld\n", ret);
    }
}

// fill in details on syscall exit
/*__attribute__((always_inline))
static inline char* set_process_create_info(PSYSMON_PROCESS_CREATE event, uint64_t pid_tid, void *task, config_s *config)
{
    void *cred = NULL;
    PSYSMON_EVENT_HEADER nonHeader = NULL;
    char *ptr = NULL;
    volatile uint32_t extLen = 0;
    void *p_task;

    // set the pid
    event->m_ProcessId = pid_tid >> 32;

    // set the process objects (task ptrs)
    p_task = (void *)deref_ptr(task, config->parent);

    event->m_ProcessObject = task;
    event->m_ParentProcessObject = p_task;

    // get the ppid
    event->m_ParentProcessId = (uint32_t)deref_ptr(p_task, config->pid);

    // get the session
    event->m_AuditUserId = (uint32_t)deref_ptr(task, config->auid);
    event->m_SessionId = (uint32_t)deref_ptr(task, config->ses);

    // get the creds
    cred = (void *)deref_ptr(task, config->cred);
    if (cred) {
        event->m_AuthenticationId.LowPart = (uint32_t)deref_ptr(cred, config->cred_uid);
        event->m_AuthenticationId.HighPart = (uint32_t)deref_ptr(task, config->tty);
    } else {
        BPF_PRINTK("ERROR, failed to deref creds\n");
        event->m_AuthenticationId.LowPart = -1;
        event->m_AuthenticationId.HighPart = -1;
    }

    // get the process key - this is the end of the text segment currently as it should be
    // a) randomised for a PIE executable; and
    // b) dependent on the amount of code in the process
    event->m_ProcessKey = (uint64_t)deref_ptr(task, config->mm_end_code);

    // get process start time - this is in nanoseconds and we want 100ns intervals
    event->m_CreateTime.QuadPart = (deref_ptr(task, config->start_time) + config->bootNsSinceEpoch) / 100;

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));
    extLen = deref_filepath_into(ptr, task, config->exe_path, config);
    
    //{BPF_PRINTK("exe=%s", ptr);}

    event->m_Extensions[PC_ImagePath] = extLen;
    ptr += (extLen & (MAX_PATH - 1));
    extLen = copy_commandline(ptr, task, config);
    event->m_Extensions[PC_CommandLine] = extLen;
    ptr += (extLen & (CMDLINE_MAX_LEN - 1));
    extLen = deref_filepath_into(ptr, task, config->pwd_path, config);
        
    //{BPF_PRINTK("pwd=%s", ptr);}

    event->m_Extensions[PC_CurrentDirectory] = extLen;
    ptr += (extLen & (MAX_PATH - 1));


    return ptr;
}*/

// extract details from the arguments
/*__attribute__((always_inline))
static inline char* set_event_arg_info(
    void* eventHdr,
    config_s *config,
    uint64_t pid_tid,
    uint32_t cpu_id,
    args_s *event_args
    )
{
    void *task = NULL;

    if (eventHdr == NULL || config == NULL || event_args == NULL)
        return NULL;

    // get the task struct
    task = (void *)bpf_get_current_task();
    if (!task)
        return NULL;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    switch(event_args->syscall_id)
    {
        // int execve(const char *filename, char *const argv[], char *const envp[]);
        // int execveat(int dfd, const char *filename, char *const argv[], char *const envp[]);
        case __NR_execve:
        case __NR_execveat:
        {
            if (config->events[SYSMONEVENT_CREATE_PROCESS_EVENT_value]) {
                // only record successful process creations
                if (event_args->return_code != 0)
                    return NULL;
                //eventHdr->m_EventType = ProcessCreate;
                //PSYSMON_PROCESS_CREATE event = &eventHdr->m_EventBody.m_ProcessCreateEvent;
                return set_process_create_info(eventHdr, pid_tid, task, config);
            }
            break;
        }
        default:
            break;
    }
    return NULL;
}*/

// check and send
__attribute__((always_inline))
static inline void check_and_send_event(void *ctx, void* event, config_s *config)
{
    //size_t size = 16;
    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(struct SyscallEvent));
}
 
#endif
