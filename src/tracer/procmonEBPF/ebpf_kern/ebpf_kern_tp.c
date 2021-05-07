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


#include "ebpf_kern_helpers.c"

// generic sys_enter argument struct for traditional tracepoints. Note that
// some or all of the 'a' array can't be derefenced depending on how many
// arguments a syscall expects; attempts to do so will cause the verifier
// to reject it.
struct tracepoint__syscalls__sys_enter {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    __uint64_t a[6];
};

// all sys_exit arguments are the same for traditional tracepoints.
struct tracepoint__syscalls__sys_exit {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
     long ret;
};


// sys_enter for 0 arguments
SEC("tracepoint/syscalls/sys_enter0")
__attribute__((flatten))
int sys_enter0(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 1 argument
SEC("tracepoint/syscalls/sys_enter1")
__attribute__((flatten))
int sys_enter1(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 2 arguments
SEC("tracepoint/syscalls/sys_enter2")
__attribute__((flatten))
int sys_enter2(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 3 arguments
SEC("tracepoint/syscalls/sys_enter3")
__attribute__((flatten))
int sys_enter3(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 4 arguments
SEC("tracepoint/syscalls/sys_enter4")
__attribute__((flatten))
int sys_enter4(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 5 arguments
SEC("tracepoint/syscalls/sys_enter5")
__attribute__((flatten))
int sys_enter5(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];
    event_args->a[4] = args->a[4];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 6 arguments
SEC("tracepoint/syscalls/sys_enter6")
__attribute__((flatten))
int sys_enter6(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;
    uint32_t config_id = 0;
    config_s *config;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, config, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];
    event_args->a[4] = args->a[4];
    event_args->a[5] = args->a[5];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_exit
SEC("tracepoint/syscalls/sys_exit")
__attribute__((flatten))
int sys_exit(struct tracepoint__syscalls__sys_exit *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t cpu_id = bpf_get_smp_processor_id();
    void* eventHdr = NULL;
    args_s *event_args = NULL;
    uint32_t config_id = 0;
    config_s *config;
    uint32_t userland_pid = 0;
    char *ptr = NULL;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return 0;

    // retrieve map storage for event args
    // this was created on the preceding sys_enter
    // if the pid_tid is in our map then we must have stored it
    event_args = bpf_map_lookup_elem(&args_hash, &pid_tid);
    if (!event_args)
        // otherwise bail
        return 0;

    // set the return code
    event_args->return_code = args->ret;

    // retrieve map storage for event
    eventHdr = bpf_map_lookup_elem(&event_storage_map, &cpu_id);
    if (!eventHdr)
        return 0;

    /*ptr = set_event_arg_info(eventHdr, config, pid_tid, cpu_id, event_args);
    if (ptr != NULL && ptr > eventHdr) {
        eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
    } else {
        eventHdr->m_EventSize = 0;
    }*/

    check_and_send_event((void *)args, eventHdr, config);

    // Cleanup
    bpf_map_delete_elem(&args_hash, &pid_tid);

    return 0;
}



